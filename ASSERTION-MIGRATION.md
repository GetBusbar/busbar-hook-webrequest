# Ordinary assertion migration

Historical core source: a35493a5e74cc935ff7dcc15c1af869290da91cb. Incremental source; generated suite stays enabled while required assertions remain unmigrated.

| Historical dependency/assertion | Current ordinary destination/status |
|---|---|
| `settings_as_the_kernel_resolves` reference resolution | `reference_url.rs` and `declared_secrets.rs` directly invoke production `secret_fields::resolve_declared_fields`, with unchanged success/refusal expectations. Declaration-only loads use ConnTable::Probe (no host calls); duplicate support-host tests remain in conformance.rs, not deleted globally |
| forwarder clock-only ServicesDouble | production `KernelServices::new().with_mono_clock(now_ns)`, same actual loader deadline clock |
| real forwarder requests/lifecycle/configure/failure/canary behavior | existing `forwarder.rs` assertions retained unchanged; now binds production Connector/Dispatched TCP+HTTP directly; no kit refs in forwarder.rs |
| generated behavior parity / exact crossing / lifecycle / refresh / short-order-buffer | existing generated conformance suite retained pending ordinary equivalents |
| kind ABI/layout/Statement/wrongkind/connection isolation/failingready/no-table negatives | retained pending core loader owner destination ACK |
| moved count comparator | framework selfcheck; not yet retired |
| emitted credentials canary | retained generated until direct output/log coverage equivalence demonstrated |
| plane class/layout, transport frame-piece, outbound auth three cases, newer-store-schema | kind-conditional suite no-op for this hook |
| needs declaration/profile | retained generated pending ordinary equivalents |
| initialized URL/response/echo byte wiping including unwind and unwiped negative control | `target_custody.rs` now locally watches only registered initialized exclusive owner prefixes immediately before actual System deallocation. All real owner wipe/reallocation/byte-count assertions and unwiped negative control retained. Old observer reentry/process_vm_readv syscall-error flags retire as observer-selfchecks: the local Cell state and volatile pre-free direct reads perform no allocation, syscall or remote-memory read. |
| linked raw cancellation/lifecycle frame tests | `hook-webrequest/src/tests/door_tests.rs` lifecycle module retained; raw-host test_support remains pending migration |
| TLS far endpoint, real TCP+HTTP host | support macro retained; must migrate to local ordinary actual connector and TLS endpoint before deletion |

No kit dependency has been removed while it still supplies live assertions. No replacement shared framework introduced. Same-SDK busbar-kernel is a dev-only actual product dependency; SDK refs, lock sources and versions unchanged; lock dependency membership adds the actual KernelServices dev dependency. Build/test execution must use centralized lane; rustfmt and diff checks only so far.

## Monday audit composition

Both source histories are retained. The donor's concurrent-partial-configure fix is composed with the later typed Result API, applied-configuration mutex and complete checkpoints; the repeated race test is retained using that API. The mutex serializes the read/merge/checkpoint/swap transaction.

The donor's status-drift fixes retain the operator's URL spelling and timeout JSON value. The additional raw URL owner is wiped by Target::drop; configure's pre-commit raw URL is held in the existing zeroizing Text guard. The initialized-owner custody test now watches both actual URL serializations. Checkpoints preserve the same desired spelling/value, so recovery retains both drift status and the clamped effective timeout; an ordinary replay test asserts both.

The donor's JSON-object-only settings check is retained with the current sanitized typed-setting refusals and direct typed Config/Text deserialization, including failed partial parses (an initial full Value parse was rejected during source review because it could discard partially parsed credentials before any zeroizing wrapper existed). Percent-decoded and per-part canary tests, strengthened clamp-warning needles and metadata-host refusal, and shared contract JSON-depth implementation are retained. The inconsistent NAT64/6to4/Teredo embedded-loopback carve-out is corrected per the audit: only actual loopback spellings receive the sidecar exception. The earlier contradictory allow assertion is replaced by the donor's blocked vectors, not retained as a history-based bug.

Source review and native validation remain separate. No golden, oracle registry or SDK pin was changed.
