// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::borrow::Cow;
use std::ops::Deref;

use busbar_contract::abi::sdk::cred::Held;

// Readable transient text and URL fragments use the standard wiping owner. SDK Held remains
// opaque and is reserved for material that must not be read back by plugin code.
pub(crate) type Text = zeroize::Zeroizing<String>;
pub(crate) type Parts = zeroize::Zeroizing<Vec<String>>;

pub(crate) struct ParsedUrl(Option<url::Url>);

impl ParsedUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, url::ParseError> {
        url::Url::parse(text).map(Self::new)
    }

    pub(crate) fn new(url: url::Url) -> Self {
        Self(Some(url))
    }

    pub(crate) fn into_url(mut self) -> url::Url {
        self.0.take().expect("owned parsed URL")
    }
}

impl Deref for ParsedUrl {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned parsed URL")
    }
}

impl Drop for ParsedUrl {
    fn drop(&mut self) {
        if let Some(url) = self.0.take() {
            drop(Held::new(url.into_string()));
        }
    }
}

pub(crate) fn wipe_url(url: &mut url::Url) {
    let empty = url::Url::parse("about:blank").expect("constant URL");
    drop(ParsedUrl::new(std::mem::replace(url, empty)));
}

/// A borrowed valid UTF-8 phrase, or its owned lossy decoding kept in wiping custody.
pub(crate) struct Phrase<'a>(Cow<'a, str>);

impl<'a> Phrase<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self::observed(Self(String::from_utf8_lossy(bytes)))
    }

    /// The test-only observer borrows the initialized owner.
    #[cfg(all(test, target_os = "linux"))]
    fn observed(phrase: Self) -> Self {
        if let Cow::Owned(text) = &phrase.0 {
            crate::owner_custody_tests::observe(text.as_bytes());
        }
        phrase
    }

    #[cfg(not(all(test, target_os = "linux")))]
    fn observed(phrase: Self) -> Self {
        phrase
    }
}

impl Deref for Phrase<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl Drop for Phrase<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(text) = &mut self.0 {
            drop(Held::new(std::mem::take(text)));
        }
    }
}

pub(crate) struct Failure(pub(crate) busbar_contract::abi::sdk::exchange::OpFailure);

impl Drop for Failure {
    fn drop(&mut self) {
        use busbar_contract::abi::sdk::conn::ConnFailure;
        use busbar_contract::abi::sdk::exchange::OpFailure;
        match &mut self.0 {
            OpFailure::Unbuilt(text)
            | OpFailure::Conn(ConnFailure::Failed(text) | ConnFailure::Refused(text)) => {
                drop(Held::new(std::mem::take(text)));
            }
            _ => {}
        }
    }
}

/// Keep a failed exchange's raw cause guarded while its earlier head is interpreted too.
pub(crate) struct FailedResponse(Option<busbar_contract::abi::sdk::exchange::ExchangeFailure>);

impl FailedResponse {
    pub(crate) fn new(failure: busbar_contract::abi::sdk::exchange::ExchangeFailure) -> Self {
        #[cfg(all(test, target_os = "linux"))]
        crate::owner_custody_tests::observe_failure(failure.cause());
        Self(Some(failure))
    }

    pub(crate) fn head(&self) -> Option<&busbar_contract::abi::sdk::exchange::ExchangeResponse> {
        self.0.as_ref().and_then(|failure| failure.head())
    }

    pub(crate) fn into_failure(mut self) -> Failure {
        Failure(self.0.take().expect("owned failed response").into_cause())
    }
}

impl Drop for FailedResponse {
    fn drop(&mut self) {
        if let Some(failure) = self.0.take() {
            drop(Failure(failure.into_cause()));
        }
    }
}
