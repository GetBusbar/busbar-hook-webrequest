// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ops::Deref;

use busbar_contract::abi::sdk::cred::Held;

#[derive(Default)]
pub(crate) struct Text(pub(crate) String);

impl Deref for Text {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Text {
    fn drop(&mut self) {
        drop(Held::new(std::mem::take(&mut self.0)));
    }
}

pub(crate) struct Parts(pub(crate) Vec<String>);

impl Parts {
    pub(crate) fn into_vec(mut self) -> Vec<String> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for Parts {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Parts {
    fn drop(&mut self) {
        drop(Held::new(std::mem::take(&mut self.0)));
    }
}

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
            drop(Held::new(String::from(url)));
        }
    }
}

// Consume only Url's owned serialization through its public conversion. The parser's private
// scratch is outside this owner; no private representation or allocation capacity is accessed.
pub(crate) fn wipe_url(url: &mut url::Url) {
    let empty = url::Url::parse("about:blank").expect("constant URL");
    drop(ParsedUrl::new(std::mem::replace(url, empty)));
}

// Only the returned tree is owned here, not serde's private parser scratch or error storage.
pub(crate) struct SettingsValue(pub(crate) serde_json::Value);

impl Deref for SettingsValue {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SettingsValue {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(text) => {
                    drop(Held::new(std::mem::take(text)));
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
                serde_json::Value::Object(items) => {
                    for (key, mut value) in std::mem::take(items) {
                        drop(Held::new(key));
                        wipe(&mut value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
