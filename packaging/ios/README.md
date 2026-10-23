# iOS Rust and packet-flow groundwork

`build-ph-ios-xcframework.sh` builds `ph` for arm64 iOS devices and arm64
simulators, type-checks the Swift packet-flow bridge against both Apple SDKs,
and packages the C header and Rust static libraries as `Ph.xcframework`. It
targets iOS 15.0 and uses a fresh temporary Cargo target directory for each
invocation, so cached objects built for another Apple SDK or deployment target
cannot enter the package. The temporary build directory is removed on exit.
The script uses the locked, offline Cargo dependency set, does not install
targets, and refuses to overwrite an existing output. Install the Rust targets
it reports as missing, then run:

```sh
bash packaging/ios/build-ph-ios-xcframework.sh
```

The default output is `target/ios-xcframework/Ph.xcframework`. An alternate
output directory may be passed as the first argument.

Consumers must set an iOS deployment target of at least 15.0 and link the
`CoreFoundation` and `Security` Apple frameworks used by the Rust static
library. The build script type-checks the Swift bridge and creates the
XCFramework; it does not build or sign an app or Network Extension.

`ZprPacketFlowBridge` connects `NEPacketTunnelFlow` to the Rust adapter through
a local Unix datagram socket pair. It bounds queued host-to-engine packets and
stops the bridge rather than silently dropping packets when the queue fills.
The host must configure its Network Extension routes before starting the
bridge. The bridge itself does not change routes, DNS, firewall state, or
system configuration.

This directory is not an iOS app or Network Extension target. App and extension
bundle identifiers, entitlements, app-group storage, protected identity
handoff, route/DNS policy, signing, and physical-device validation remain
unimplemented. The bridge expects an absolute adapter config path and does not
provide keychain-backed credentials.
