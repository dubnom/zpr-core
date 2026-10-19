# Adapter Platform Support Plan

**Status:** Proposed engineering plan
**Snapshot:** 2026-10-04

This plan covers the `ph` packet-handler adapter running on Windows, Android,
and iOS. The aim is to preserve one ZPR packet-processing and authorization
implementation while integrating with each platform's native tunnel, routing,
permission, and lifecycle APIs. This is not a plan to port WireGuard's protocol
or UI.

## Current Baseline

- Linux has the primary TUN backend, Linux route/address operations, and the
  exercised integration path. The adapter CI workflow runs on Ubuntu and the
  published artifact is `release-linux-x86_64.tar.gz`.
- macOS has a native `utun` implementation in `adapter/ph/src/sys/macos`, but
  it is not in the adapter CI matrix. It currently supports one TUN queue and
  IPv6 address management only; named interfaces must use the `utunN` form.
  Native Apple Silicon compilation/unit validation now passes locally; see
  the October 7 progress below. This is not connected-adapter certification.
- Windows has no `ph` system/TUN backend.
- Android and iOS have no `ph` platform integration. Android-specific packet
  steering conditionals are not, by themselves, a working Android adapter.

The porting boundary is wider than TUN creation. `ph` also uses Unix datagrams,
Unix listeners/streams, and ancillary file-descriptor passing in its control,
capture, and queue paths. Those assumptions must be isolated before the engine
can be hosted by Windows services or mobile tunnel extensions.

## WireGuard Patterns To Reuse

WireGuard-Go keeps the packet engine behind a small device contract
([`tun.Device`](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun.go))
and provides separate OS-specific TUN implementations. Its Windows backend
uses Wintun; Android passes the descriptor obtained from `VpnService` through
JNI to the userspace engine; Apple hosts the engine inside a
`NEPacketTunnelProvider` and passes the Network Extension tunnel descriptor.
Windows also treats tunnel service management, routing, and firewall state as
platform responsibilities instead of embedding them in packet processing.

For ZPR, borrow the boundary and lifecycle pattern, not WireGuard's protocol,
configuration, authorization, or platform UI. Keep ZPR bootstrap identity,
node connectivity, certificate validation, and Visa Service authorization
under the existing `ph` implementation.

## Phased Work

### 0. Define The Support Contract

- Specify what “supported” means per platform: builds, installation, tunnel
  start/stop, reconnect, route/DNS behavior, and tested ZPR traffic.
- Select initial architectures: Linux x86-64 and arm64; macOS arm64 and x86-64
  where maintainable; Windows x86-64 first; Android arm64 first; iOS arm64
  device first. Add other architectures only with CI and device coverage.
- Keep platform-specific privilege, entitlement, certificate/key storage, and
  upgrade requirements explicit.

### 1. Isolate The Shared Engine

- Introduce a packet-device boundary for batched packet reads/writes, packet
  metadata, MTU, interface events, and shutdown. Avoid requiring an OS file
  descriptor: Android can supply one, Apple supplies a packet-tunnel endpoint,
  and Wintun exposes its own session API.
- Separate route/address/DNS setup and socket protection from the packet engine
  behind platform adapters.
- Audit Unix-only control and capture channels, especially ancillary FD
  passing. Keep the current fast Unix path on Linux/macOS, but define portable
  message/control interfaces for Windows and mobile hosts.
- Add a fake packet device so authorization, packet flow, shutdown, reconnect,
  and error behavior can be tested without privileged TUN access.

### 2. Stabilize macOS

**Local progress, 2026-10-07:** `cargo test --locked -p ph` passes natively on
Apple Silicon: 246 library and 267 binary tests, with one ignored test in each
runner. `cargo build --locked -p ph --bin ph` and `ph adapter --help` also pass.
No utun device, route, DNS setting or live organization was changed.

Six new unprivileged Mac tests exercise name/unit bounds, pre-kernel prefix/MTU
rejection, IPv6 masks, global/scoped address recognition, prefix bounds and
unsupported queues. The backend now checks socket failure before creating an
owned descriptor, prevents interface-unit overflow, validates configuration
before tunnel creation and recognizes IPv6 addresses without requiring a scope
suffix. Address addition/removal is serialized.

The separate enrollment project now provides an Apple Silicon per-user
Keychain-backed development wizard/app/DMG. It neither installs this runtime
nor issues its credentials. Secure enrollment-to-runtime handoff remains
unfinished; do not bridge it by exporting the user's Keychain key to a root
service. See the [Mac enrollment guide](../zpr-visaservice/zpr-dashboard/README.md#mac-enrollment-app-and-adapter-validation-development).

Strict Clippy remains blocked by existing `libnode2` lints and an existing
capture-worker unhandled partial-write lint, outside this increment. Build/unit
success is not a claim that lint, privileged packet flow or lifecycle gates pass.

**Privileged local smoke:** explicitly administrator-approved native
utun create/configure/close now passes on this Apple Silicon host. The opt-in
[runner](integration-test/macos-utun-smoke.sh) builds as the ordinary desktop user
and elevates only the exact ignored library test. It uses a kernel-assigned fresh
interface, random per-run ULA host aliases (/128), MTU 1400 then 1280, duplicate add/removal
checks and two teardown/recreation cycles. Descriptor close removes the interface
even before a lifecycle error is reported. Existing interfaces, IPv4/IPv6 default
routes and DNS snapshots match before/after. No default route or DNS is configured,
no existing interface is named/modified, and no ZPR credentials/traffic are used.

Run deliberately on a Mac with administrator authorization:

```sh
sh integration-test/macos-utun-smoke.sh --allow-temporary-utun
```

The test is ignored by ordinary Cargo runs and additionally requires
`ZPR_MACOS_UTUN_SMOKE=1` plus root. Cargo never runs elevated. The runner uses
cached sudo authorization or the macOS administrator dialog, and reports failure
if host snapshots differ rather than attempting automatic network repair.
Ordinary `cargo test --locked -p ph` now has 246 library / 267 binary passing
tests and **two ignored tests in each runner**. This smoke establishes native
interface/address/MTU teardown only—not packet forwarding, full route rollback,
DNS lifecycle, sleep/wake, production identity admission or credential handoff.

**Development install package, 2026-10-09:** `packaging/macos/build-adapter-pkg.sh`
builds an Apple Silicon package containing native `ph`/`ph-cli` binaries and a
root LaunchDaemon. It requires a separately provisioned, root-owned mode-0600
adapter profile; absent or unsafe configuration leaves the service disabled.
The package does not create identities, issue credentials, copy the user's
Keychain key, install during this task, or change routes/DNS. The explicit
unsigned-development option is not suitable for distribution. Credential
issuance/handoff, Developer ID signing/notarization, route/sleep lifecycle and
real ZPR packet-flow validation remain release gates; see
[`packaging/macos/README.md`](packaging/macos/README.md).

**CI build/package, 2026-10-18:** `.github/workflows/adapter.yml` now defines
an Apple Silicon macOS job that runs the `ph` and `ph-cli` unit tests, builds
the unsigned development package, checks the arm64 binaries and CLI help, and
uploads the package for one day. Its first GitHub Actions run is still pending.
It does not install or sign the package, run the privileged utun smoke, or
validate packet forwarding.

- Add a permission-gated utun smoke test to CI where runner authorization is
  safe and explicit; distinguish native interface checks from packet-flow tests.
- Test IPv6 address lifecycle, route setup, MTU, sleep/wake, adapter shutdown,
  and reconnect. Document the current single-queue limitation until a tested
  multi-queue design exists.
- Gate macOS release claims on a real host integration test, not cross-compiling
  alone.

### 3. Implement Windows

- Add a Wintun-backed packet-device implementation and Windows-specific
  interface/address/route management.
- Replace Unix local IPC and signal assumptions with named pipes or another
  authenticated local IPC mechanism. Define service installation, upgrade,
  privilege separation, firewall/kill-switch behavior, and clean uninstall.
- Build and test on Windows x86-64 first; add Windows arm64 only after toolchain,
  Wintun, and package support are verified.
- Validate adapter bootstrap, ZPR link establishment, allowed/denied flows,
  visa revocation, reconnect, and service recovery in a Windows VM.

### 4. Implement Android

- Host the engine in a native library and connect it to the TUN file descriptor
  from Android `VpnService`; use a narrow JNI/FFI start, stop, and status API.
- Handle user VPN consent, foreground-service requirements, always-on mode,
  process recreation, network changes, per-app routing policy, and Android
  Keystore-backed credentials.
- Start with arm64 devices plus an x86-64 emulator. Test permission denial,
  background/foreground transitions, sleep, roaming, and no traffic bypass when
  ZPR is unavailable.

### 5. Implement iOS

- Host the engine in a Network Extension packet-tunnel provider and bridge its
  packet flow to the Rust engine through a narrow FFI boundary.
- Add the required Network Extension entitlement, app-group/config sharing,
  profile approval, key storage, and extension-safe startup, reassertion, and
  teardown behavior.
- Test on physical arm64 devices and the iOS simulator where supported. Verify
  route/DNS settings, network changes, extension termination/restart, and
  system-enforced no-bypass behavior.

**Local groundwork, 2026-10-13:** The Rust library now cross-compiles for
`aarch64-apple-ios` when `zpr-ext` is resolved to the adjacent workspace source
with iOS socket cfg support. The iOS TUN shim accepts a host-supplied datagram
socket and deliberately refuses to configure addresses itself; regression tests
cover that boundary and verify that iOS packets have no platform packet-info
header. The production dependency
is still pinned to `zpr-ext-v0.5.3`, which lacks those iOS cfgs, so the normal
locked build remains blocked until the dependency fix is released and adopted.
There is not yet a Network Extension target/provider, FFI runtime entry point,
packet-flow pump, entitlement, or iOS app-group configuration. This is build
groundwork only, not a usable or certified iOS adapter.

**Cross-target compile follow-up, 2026-10-13:** The complete `ph` binary and
test code now type-check for `aarch64-apple-ios` with the same local `zpr-ext`
override. The optional DNS stub deliberately refuses to open an upstream
connection on iOS until the Network Extension host can guarantee that traffic is
routed through the tunnel; it must not silently fall back to the physical
interface. The iOS-target tests compile but require a native iOS test host to
execute.

**Dependency and library build, 2026-10-18:** Core now pins `zpr-ext` to exact
upstream commit `7dfee1cb41a13c6cbf7f350eb436009a99c22c0b`, which adds the
missing iOS socket cfgs not present in `zpr-ext-v0.5.3`. Locked
`cargo check --package ph --target aarch64-apple-ios` and a release
`cargo build --package ph --lib --target aarch64-apple-ios` pass locally. CI
now defines the same Rust-library build; its first run is pending. A full iOS
binary link currently fails in AWS-LC with undefined `___chkstk_darwin` on this
Xcode 27 host, so no executable/package claim is made. The library build is an
`rlib`, not a Swift-callable framework or app. Network Extension host/FFI,
packet-flow integration, entitlements, and app-group packaging remain absent.

### 6. Release Gates

**Publication reconciliation, 2026-10-15 UTC (2026-10-14 EDT):** Native macOS
`cargo test` passes, including 293 `ph` library tests with two ignored tests.
This source checkpoint includes the iOS cfg and packet-worker changes on
`work/macos-tun-address`; this does not move them to the main branch, adopt a
new `zpr-ext` dependency tag, execute iOS tests, or certify Linux `io_uring`
behavior on macOS. The earlier local-override iOS build evidence remains
groundwork only. Sustained live recovery and the platform release gates below
remain open.

A platform is not supported by a successful build alone. Each release target
must pass:

- CI compilation and unit tests for the target OS and architecture.
- Native tunnel start/stop, packet forwarding, ZPR bootstrap, and Visa Service
  authorization tests.
- Allowed and denied flows, policy-change revocation, reconnect after network
  changes, and clean shutdown with no packet leakage.
- Installation/upgrade/uninstall checks and platform-specific privilege,
  entitlement, and credential-storage review.

Keep Linux as the reference implementation while porting. Do not weaken ZPR
identity checks, fail-open behavior, or certificate verification to accommodate
a platform API.