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

- Add macOS CI for compilation, unit tests, and a permission-gated utun smoke
  test; distinguish simulator/build checks from real packet-flow tests.
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

### 6. Release Gates

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