# iOS Rust and packet-flow groundwork

`build-ph-ios-xcframework.sh` builds `ph` for arm64 iOS devices and arm64
simulators, type-checks the Swift packet-flow bridge against both Apple SDKs,
and packages the C header and Rust static libraries as `Ph.xcframework`. It
uses the locked, offline Cargo dependency set and does not install targets or
overwrite an existing output. Install the Rust targets it reports as missing,
then run:

```sh
bash packaging/ios/build-ph-ios-xcframework.sh
```

The default output is `target/ios-xcframework/Ph.xcframework`. An alternate
output directory may be passed as the first argument.

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
