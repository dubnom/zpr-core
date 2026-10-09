# macOS Adapter Package (Development)

This package is for Apple Silicon Macs running macOS 13 or later. It installs
native `ph` and `ph-cli` binaries plus a root LaunchDaemon. It does not enroll a
device, issue credentials, or configure a ZPR organization. An administrator
must provision a valid adapter profile and its credentials before the daemon
can start.

## Build

From the `zpr-core` repository on Apple Silicon:

```sh
sh packaging/macos/build-adapter-pkg.sh 0.1.0 /tmp/zpr-adapter.pkg --development-unsigned
```

For an installer intended for managed distribution, set
`ZPR_MACOS_INSTALLER_IDENTITY` to a valid Developer ID Installer identity and
omit `--development-unsigned`. Signing alone does not notarize the package.
Do not distribute an unsigned development package or bypass Gatekeeper.

## Provisioning

Before enabling the service, an administrator must create
`/Library/Application Support/ZPR/Adapter/adapter.toml` with mode `0600`,
owned by `root:wheel`, using `adapter.example.toml` as a field reference. The
CA, adapter Noise certificate/private key, and bootstrap key referenced by the
profile must also be provisioned as root-owned files with restrictive modes.
Use a device-specific identity approved for the intended organization. The
development enrollment Keychain key is not the adapter runtime credential and
must not be exported or copied to this root service.

Leave `tun_if` and `zpr_addr` unset so macOS assigns a fresh `utun` interface
and PH can use the address granted by Visa Service. The adapter currently
supports one queue and IPv6 only. The package installs no default route and no
DNS configuration. ZPR route reachability and policy must be verified with the
organization administrator before relying on traffic through the adapter.

Install the package with the macOS Installer after the profile and runtime
credentials are provisioned. The postinstall step starts the daemon only when
the profile is a regular root-owned mode-0600 file; otherwise it leaves the
service disabled. Check status with:

```sh
sudo launchctl print system/com.zpr.ph.adapter
tail -f /var/log/zpr/ph-adapter.log
```

To stop it, run `sudo launchctl bootout system /Library/LaunchDaemons/com.zpr.ph.adapter.plist`.
Removing the package does not revoke the device identity. Revocation and
credential retirement remain administrator responsibilities.

This package is a local development foundation, not a certified production
release. Full enrollment-to-runtime credential issuance/handoff, packet-flow
certification, sleep/wake recovery, Intel support, signing/notarization and
uninstall testing remain release gates.