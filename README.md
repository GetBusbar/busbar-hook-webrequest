<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-hook-webrequest

A transparent HTTP forwarder that POSTs each hook op envelope (decide/transform/notify/configure/describe/status) to an operator-configured URL and returns the capped JSON reply: a busbar first-party kind:hook plugin (dlopen cdylib).

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `hook` | `webrequest` | `busbar-hook-webrequest-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-hook-webrequest/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-hook-webrequest/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-hook-webrequest/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-hook-webrequest)

**v1.5.0.** The first-party, signed `kind: hook` plugin for
[busbar](https://getbusbar.com): a transparent HTTP forwarder that POSTs
each hook op envelope (`decide` / `transform` / `notify` / `configure` /
`describe` / `status`) to an operator-configured URL and returns the
capped JSON reply verbatim. Busbar's own `hooks::wire` normalizers parse
that reply, so this plugin is a pure network relay — it adds a hop, never
a second copy of the hook wire semantics.

It implements busbar's `HookHandler` trait (via
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract)'s
`abi::sdk`) and has both doors: built as a `cdylib` it is a signed tarball
busbar `dlopen`s in-process (never spawned as a separate process), and as
an `rlib` a busbar build can link it (`linked::HOOK`) — the same boundary
either way. `tests/conformance.rs` proves the two doors are one hook.


- **Migration** off the retired socket/webhook hook transport: point
  `settings.url` at the same service a `route: webhook` pool used and the
  wire is compatible (`{op, ...projection}` POST → a
  `{order|abstain|reject|restrict|rewrite}` reply).
- **Isolation** of untrusted hook logic: the untrusted brain runs
  *remotely* behind this trusted, signed, `dlopen`'d forwarder. The
  forwarder — not busbar core — owns the outbound HTTP call.

### The security stance

- **SSRF-guarded** (`src/net_guard/mod.rs`): the configured URL is validated
  at `open`/`configure` — loopback sidecars are allowed; link-local /
  IMDS / RFC1918 / CGNAT / ULA / cloud-metadata / alternate-IPv4
  encodings are blocked; plaintext `http://` is permitted only to
  loopback. A host NAME is resolved and checked again on every connect,
  so an answer that turns internal later (DNS rebinding) is refused
  before anything is dialed, and a target whose addresses rotate is
  followed.
- **Redirects disabled** on the client (`redirect::none`): a target
  cannot 30x-redirect the plugin to an internal host at runtime.
- **Tight timeouts**; the reply body is capped before allocation (64
  KiB) and depth-guarded before parse (127 levels — one below
  serde_json's own internal recursion limit, which binds first) — a
  hostile or buggy target can neither exhaust memory nor blow the
  stack.
- **Userinfo stripped** from every error string, so a `user:pass@`
  embedded in the operator's URL never reaches a logged error.
- **Grants are core-enforced, never plugin-driven**: this forwarder only
  relays whatever `payload` busbar core chose to project. Its signed
  manifest declares `needs` (the intent it must relay); core still sends
  content only if the operator also grants it.

See the doc comments at the top of [`src/lib.rs`](src/lib.rs) and
[`src/net_guard/mod.rs`](src/net_guard/mod.rs) for the full design rationale.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | The `https://` (or loopback `http://`) URL each hook op envelope is POSTed to. Validated against the SSRF guard at load and on every `configure` push; a committed push takes effect immediately (the next `decide`/`transform`/`notify` uses it), not only after a future plugin reload. |
| `timeout_ms` | no | `5000` | Per-op wall-clock timeout, clamped to `[1, 5000]` — cannot exceed the engine's reference hook budget, since a hook FFI call holds a process-wide permit until the blocking call returns (see `MAX_TIMEOUT_MS`'s doc comment in `src/lib.rs`). Independently pushable via `configure`, applied immediately. |

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs); `rust-toolchain.toml`
pins the version CI uses).

```sh
cargo build --release      # cdylib: target/release/libbusbar_hook_webrequest.{so,dylib}
cargo test                 # unit tests, the loader-seam e2e, the linked/dropped-in conformance,
                           # and the full-stack e2e (needs a busbar checkout, below)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

The one busbar crate this plugin names is `busbar-contract` (plus
`busbar-plugin-loader`, dev-only, for the conformance and e2e tests) — a
`git` dependency on [GetBusbar/busbar](https://github.com/GetBusbar/busbar)
pinned to the rev in field 1 of `.busbar-ref`. CI checks that every
manifest rev and the lockfile agree with that pin.

`tests/full_stack_e2e.rs` builds and boots the real `busbar` binary, so it
needs a busbar checkout at that same rev: `BUSBAR_CHECKOUT=<path>`, or a
sibling checkout beside this repo:

```
some-parent-dir/
├── busbar/            # at the .busbar-ref rev
└── busbar-hook-webrequest/
```

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference (`busbar-plugin-pack` is built with
`cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack`). In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_hook_webrequest.so \
    --name busbar-hook-webrequest --alias webrequest --kind hook \
    --version 1.5.0 --publisher busbar \
    --license Apache-2.0 \
    --needs-prompt rw --needs-user ro \
    --out busbar-hook-webrequest-1.5.0-x86_64-linux.tar.gz
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

`cargo test` runs both the pure unit tests (`src/lib.rs`, `src/net_guard/mod.rs`
— SSRF predicates, reply parsing/depth guard, envelope shaping) and the
end-to-end test in `tests/e2e.rs`, which loads the *built* cdylib over
the real `busbar-plugin-loader` ABI seam against a local mock HTTP
target — the same seam busbar's engine uses, so it exercises the actual
`dlopen`/FFI path rather than calling Rust functions directly. Build
under `cargo test --workspace`-equivalent (i.e. a normal `cargo build`
first, or just `cargo test`, which builds the cdylib as part of the
test run) so the e2e test finds the library; it self-skips with a
message if the cdylib isn't present.

## License

Apache-2.0. See [LICENSE](LICENSE).
