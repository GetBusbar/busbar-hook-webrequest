<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-hook-webrequest

A transparent HTTP forwarder that POSTs each decide/transform/notify op envelope to an operator-configured URL and returns the capped JSON reply (configure, status and describe are answered by the plugin itself): a busbar first-party kind:hook plugin (dlopen cdylib).

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `hook` | `webrequest` | `busbar-hook-webrequest-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-hook-webrequest/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-hook-webrequest)

**v1.6.0.** The first-party, signed `kind: hook` plugin for
[busbar](https://getbusbar.com): a transparent HTTP forwarder that POSTs
each per-request hook op envelope (`decide` / `transform` / `notify`) to an
operator-configured URL and returns the capped JSON reply verbatim. Busbar's
own reply lowering (`busbar-contract`'s `abi::sdk::hook`) parses that reply,
so this plugin is a pure network relay — it adds a hop, never a second copy
of the hook wire semantics. `configure` is applied by the forwarder itself
(the settings merge, never POSTed), and `describe` / `status` are the
forwarder's own documents, never the endpoint's.

It implements the hook kind's `Hook` trait (via
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract)'s
`abi::sdk::hook`) and has both doors: built as a `cdylib` it is a signed tarball
busbar `dlopen`s in-process (never spawned as a separate process), and as
an `rlib` a busbar build can link it (`door::door`) — the same boundary
either way. `hook-webrequest-plugin/tests/forwarder.rs` drives the same script through both doors
and checks they answer alike; `hook-webrequest-plugin/tests/conformance.rs` checks both images'
kind ABI, layout, statement and declared needs.


- **Migration** off the retired socket/webhook hook transport: point
  `settings.url` at the same service a `route: webhook` pool used and the
  wire is compatible (`{op, ...projection}` POST → a
  `{order|abstain|reject|restrict|rewrite}` reply).
- **Failures are failures.** A `decide` or `transform` whose forward fails (transport, timeout,
  a non-2xx status (including a redirect or 600–999), an empty reply (a `204` included),
  or an oversize, over-deep or not-JSON reply) FAILS the hook, so the pool's `on_error` applies. A reply
  the target sends deliberately (`{}`, `{"abstain":true}`) is an abstain. Busbar's shared reply
  lowering validates the hook reply and chooses its verdict. A `notify` is fire-and-forget.
- **Isolation** of untrusted hook logic: the untrusted brain runs
  *remotely* behind this trusted, signed, `dlopen`'d forwarder. The
  forwarder decides what is POSTed and where; the host's `http` framer
  carries it over the forwarder's one declared need.

### The security stance

- **SSRF-guarded** (`hook-webrequest/src/net_guard/mod.rs`): the plugin
  validates the literal host of the configured URL at `open`/`configure` —
  loopback sidecars are allowed; link-local / IMDS / RFC1918 / CGNAT / ULA /
  cloud-metadata / alternate-IPv4 encodings are blocked; plaintext `http://`
  is permitted only to loopback. A host NAME is resolved, checked and
  pinned by the host's loopback-allowed egress class, not by the plugin, so
  an answer that turns internal later (DNS rebinding) is refused before
  anything is dialed.
- **Redirects are never followed.** The plugin has no HTTP client of its own:
  it hands a framed request to the host's `http` framer through its one
  declared need. For `decide` and `transform`, a 3xx reply fails with "redirect
  not followed". A `notify` keeps the 1.5.5 fire-and-forget behavior: a 2xx or
  3xx acknowledges delivery without interpreting the response body; any other final status logs a dropped notification. None of these operations follows a redirect,
  so a target cannot redirect the plugin to an internal host.
- **Tight whole-request timeouts**: the configured budget covers connection establishment, send,
  and reply collection from one absolute host-clock expiry. A reply head or a Pending re-entry
  never renews it; the host timer wakes a stalled body at expiry. The outer hook deadline caps it.
  `decide`/`transform` response collection refuses a body
  beyond 64 KiB while reading it, before collecting the offending piece. A `notify`
  reads only the response head. Decision replies are depth-guarded before parse
  (past 128 levels, `MAX_REPLY_DEPTH`; serde_json's own recursion limit
  binds first and refuses a 128-deep reply as invalid JSON) — a hostile or buggy target cannot blow the stack or get an
  oversized reply relayed.
- **Userinfo stripped** from every error string, so a `user:pass@`
  embedded in the operator's URL never reaches a logged error.
- **Grants are core-enforced, never plugin-driven**: this forwarder only
  relays whatever `payload` busbar core chose to project. Its signed
  manifest declares `needs` (the intent it must relay); core still sends
  content only if the operator also grants it.

See the doc comments at the top of [`hook-webrequest/src/lib.rs`](hook-webrequest/src/lib.rs) and
[`hook-webrequest/src/net_guard/mod.rs`](hook-webrequest/src/net_guard/mod.rs) for the full design rationale.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | The `https://` (or loopback `http://`) URL each hook op envelope is POSTed to. Validated against the SSRF guard at load and when a `configure` push applies. Newly started operations use a committed target immediately; an operation already pending keeps its opening target until it completes. |
| `timeout_ms` | no | `5000` | Per-op wall-clock timeout, clamped to `[1, 5000]` — cannot exceed the engine's reference hook budget (see `MAX_TIMEOUT_MS`'s doc comment in `hook-webrequest/src/config.rs`). At open, `null` uses the default; in a partial `configure`, an absent or `null` timeout keeps the live value. |

Any other key is ignored, as 1.5.5 ignored it (so a 1.5.5 document still opens), and logged by name as a warning in the plugin's own log at `open` and when a `configure` push applies. Each push merges only its supplied settings; a refusal commits neither setting and logs the reason. An older configuration version is acknowledged without applying it or emitting settings warnings.

Acknowledged pushes return complete normalized settings through the SDK's configuration checkpoint.
The host can restore the effective URL and timeout after quarantine even when the latest push was
partial or empty. Pending operations retain their own opening target through configure or refresh.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs); `rust-toolchain.toml`
pins the version CI uses).

```sh
cargo build --release -p busbar-hook-webrequest-plugin --features dropped-in      # cdylib: target/release/libbusbar_hook_webrequest_plugin.{so,dylib}
cargo test                 # unit tests, the loader-seam forwarder test, and the linked/dropped-in conformance
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

The one busbar crate this plugin names is `busbar-contract` (plus
`busbar-plugin-loader` and the host connector/transport crates, dev-only, for
the conformance and forwarder tests) — a
`git` dependency on [GetBusbar/busbar](https://github.com/GetBusbar/busbar)
pinned to the rev in field 1 of `.busbar-ref`. CI checks that every
manifest rev and the lockfile agree with that pin.

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference (`busbar-plugin-pack` is built with
`cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack`). In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_hook_webrequest_plugin.so \
    --name busbar-hook-webrequest --alias webrequest --kind hook \
    --version 1.6.0 --publisher busbar \
    --license Apache-2.0 \
    --needs-prompt rw --needs-user ro \
    --out busbar-hook-webrequest-1.6.0-x86_64-linux.tar.gz
```

`--needs-prompt` / `--needs-user` declare this plugin's grant intent in
the signed manifest — set them to whatever the deployment's hook
`prompt:`/`user:` grant requires; core enforces the actual projection, so
the plugin can never receive more than it declares. For local
development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
reference it as a hook module — see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#hook-plugins-kind-hook)
for the `hooks:` wiring (`kind: hook`, `settings: { url: ... }`).

## Tests

`cargo test` runs the pure unit tests (`hook-webrequest/src/tests/*`: `config_tests.rs` the
settings and `configure`, `door_tests.rs` the configure merge, its checkpoints and concurrent
pushes, the sealed request parts and how a reply head is read, `echo_tests.rs`
the credential-echo canaries, `custody_tests.rs` canonical URL redaction, `owner_custody_tests.rs`
the actual door's owned error and lossy-phrase wiping on Linux, `reply_tests.rs` the reply rules and the per-op meaning of a
failure, `report_tests.rs` the `status`/`describe` documents, `wire_tests.rs` the envelope and
the request bytes against the 1.5.5 client, and `net_guard_tests.rs` the SSRF predicates) and the
plugin crate's integration tests
(`hook-webrequest-plugin/tests/`):

- `conformance.rs`: the actual linked and dropped-in images against the loader's checks: the kind
  ABI and layout, the statement against each manifest row, refusal as every other kind, the two
  images being distinct, and the declared `http` need;
- `forwarder.rs`: loads the *built* cdylib over the real `busbar-plugin-loader` ABI seam against a
  scripted far end, the same seam busbar's engine uses, so it exercises the actual `dlopen`/FFI
  path rather than calling Rust functions directly. It also covers the existing extension-status,
  notify-redirect, and non-UTF-8 Basic rules through both doors.
  It also exercises concurrent partial configuration, checkpoint replay, wrong-type refusals and
  refresh during pending completion or cancellation through both doors
  (`support/net_ban.rs` is its socket/TLS ban). Bare query/path canaries cover each operation and
  a Pending target change; real HTTP connector tests send a head and stall the partial body to
  distinguish the configured whole-request timeout from the longer dispatcher deadline;
- `target_custody.rs`: on Linux, registers only owned URL serializations (including the copies a
  url-replacing `configure` supersedes) and the response reader's
  reason/body/field allocations, and checks initialized bytes before
  deallocation on return and unwind, with an unwiped control;
- `declared_secrets.rs` and `reference_url.rs`: `url` is declared reference-capable and not a
  secret, so a `{env:}` reference there resolves in place and a literal passes as written.

`cargo test` builds the cdylib as part of the run.

## Differences from 1.5.5

Valid, well-formed settings and replies behave as in 1.5.5 except where an entry below says
otherwise. The historical baseline here is `webrequest-hook` tag `v1.0.6`, whose `.busbar-ref`
pins busbar 1.5.5; core 1.5.5 registers that external plugin in `plugins.yaml`.

- **Only 2xx replies carry decisions or rewrites.** The 1.5.5 client's treatment of 600–999 as
  successful responses is no longer preserved. These statuses fail the hook so `on_error` applies.
  A notify still acknowledges 2xx/3xx delivery without reading a reply; other final statuses log a
  dropped notification.
- **Invalid percent-decoded UTF-8 userinfo is refused at open and configure.** The 1.5.5 client
  silently omitted a non-UTF-8 username or replaced a non-UTF-8 password with an absent password.
  The new refusal echoes no credential and a refused configure preserves the complete live target.
  Valid UTF-8 credentials, including percent-encoded Unicode and password colons, are unchanged.
- **A user name holding an encoded `:` is refused.** A `settings.url` such as
  `https://us%3Aer:pw@host/` is refused at `open` and NACKed by `configure` (BUSBAR-7153), in words
  that echo none of the userinfo. The 1.5.5 client sent it as `Basic base64(us:er:pw)`, which a
  receiver reads as user `us` (RFC 7617: the first `:` ends the user-id), so the target saw the
  wrong credential. Write a `:` meant for the password after the first `:`.
- **A failed `decide` or `transform` is a failure.** A transport failure, timeout, error status,
  redirect or invalid reply fails the hook, so the pool's `on_error` applies. The historical
  `v1.0.6` forwarder answered `{}` for either operation instead. Later external-plugin source
  introduced a fallible `decide_result`; the released tag itself did not expose that failure.
- **A 3xx reply fails `decide` and `transform`** ("redirect not followed"). The 1.5.5 forwarder did
  not follow it either but read the redirect's body as the reply; busbar 1.5.5's sidecar contract
  already called any non-2xx status an error and required a reply to ride a 2xx. A `notify` still
  counts a 3xx as delivered.
- **`timeout_ms: null` in a `configure` push keeps the live timeout** and is acknowledged; 1.5.5
  NACKed it although `open` accepted the same `null`. The normalized settings this forwarder
  reports (`status`, the configuration checkpoint) carry `null` for a timeout that was never set,
  so they can be pushed back as they are.
- **`status` reports the settings as the operator wrote them**: `url` is the configured text and
  `timeout_ms` the written value (`null` when none), where `v1.0.6` reported only `target_host` and the
  effective timeout. Busbar's drift check compares these values with the desired settings and
  publishes only key names, so the historical form could not match the desired `url` key and
  differed for every defaulted or clamped timeout. `target_host` is unchanged.

## License

Apache-2.0. See [LICENSE](LICENSE).
