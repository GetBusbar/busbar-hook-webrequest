// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOTH-WAYS CONFORMANCE of `busbar-hook-webrequest`: busbar's PUBLISHED suite
//! (`busbar_plugin_loader::conformance_suite!`, at the busbar commit this repo pins in `.busbar-ref`),
//! run by this repo. It loads the LINKED door (the logic crate's `door::door`) and the BUILT cdylib
//! (`busbar-hook-webrequest-plugin`) through busbar's real plugin loader and drives both with the
//! hook kind's script over `conformance.json`. The forwarder's one outbound need (`http`) is carried
//! by busbar's own connector, composed as the root composes it (`conformance_host`, rendered by the
//! fleet template), to the suite's TLS far end on loopback, which answers the hook route the way an
//! operator's endpoint does; the plugin holds no socket and no TLS. The forwarder's own wire proofs
//! (the 1.5.5 envelope byte for byte, the red arms, the socket ban) are `forwarder.rs`.
#[path = "support/conformance_host.rs"]
mod conformance_host;

/// The operator's endpoint, as the far end answers it: once the whole POST (head and its
/// `content-length` body) is read, the route the settings name answers its order — `/route` the
/// one the requests read, `/refreshed` the one the refresh moves the target to (so the decide
/// after the refresh proves the new target is the one asked).
fn endpoint(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if seen.len() < end + body {
        return None;
    }
    let target = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("");
    let reply: &[u8] = match target {
        "/route" => br#"{"order":[9,3,7]}"#,
        "/refreshed" => br#"{"order":[7,9]}"#,
        _ => return Some(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec()),
    };
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        reply.len()
    )
    .into_bytes();
    out.extend_from_slice(reply);
    Some(out)
}

/// The host the suite binds the forwarder over, with the far end its settings name listening.
fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> {
    conformance_host::far_end(endpoint);
    conformance_host::host(wake, anchors)
}

busbar_plugin_loader::conformance_suite! {
    door: busbar_hook_webrequest::door::MACRO_DOOR,
    cdylib: "busbar_hook_webrequest_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
}
