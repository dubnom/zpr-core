use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

// TODO: This logging is used to debug the use of local commands for TUN address management. Remove once we use syscalls.
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::macos::tun;
use crate::zprtun::ZprTunError;
use std::process::Command;

const COMMAND_IFCONFIG: &str = "/sbin/ifconfig";

pub struct ZprTun {
    inner: tun::Tun,
    mtx: std::sync::Mutex<()>,
}

impl From<tun::TunError> for ZprTunError {
    fn from(e: tun::TunError) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    pub fn name(&self) -> &str {
        self.inner.get_name()
    }

    fn new(inner: tun::Tun) -> Self {
        ZprTun {
            inner,
            mtx: std::sync::Mutex::new(()),
        }
    }

    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// On macOS if the name is specificed, it must be of the form `utun[0-9]+`.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }
        let addr = address.ok_or_else(|| {
            ZprTunError::PlatformError(String::from("address is required on macos"))
            // TODO: Temporary
        })?;
        let mut bldr = tun::Tun::builder(addr.into());
        bldr.with_address(addr);
        if let Some(name) = ifname {
            bldr.with_tun_name(&name);
        }
        let dev = tun::Tun::create(&bldr)?;
        Ok(vec![ZprTun::new(dev)])
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    pub fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        validate_prefix(prefix_len)?;
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        if self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "add_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("alias");
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to set address on {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        validate_prefix(prefix_len)?;
        let _lock = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::other("Mutex lock failed"))?;
        if !self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "clear_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("-alias"); // <-- note the MINUS here
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to clear addresses {} on {}: {}",
                    addr,
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        if addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "has_address with IPv4 is not supported on macos",
            ));
        }
        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        //         inet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
        //         nd6 options=201<PERFORMNUD,DAD>
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to show addresses for {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        let out_str = String::from_utf8_lossy(&output.stdout);
        Ok(ifconfig_has_address(&out_str, addr))
    }
}

fn validate_prefix(prefix_len: u8) -> std::io::Result<()> {
    if prefix_len > 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "IPv6 prefix length must be between 0 and 128",
        ));
    }
    Ok(())
}

fn ifconfig_has_address(output: &str, address: IpAddr) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("inet6")
            && fields
                .next()
                .and_then(|value| value.split('%').next())
                .and_then(|value| value.parse::<IpAddr>().ok())
                == Some(address)
    })
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_global_and_scoped_ipv6_addresses_exactly() {
        let output =
            "utun2: flags=8051\n\tinet6 fe80::1%utun2 prefixlen 64\n\tinet6 fd00::1 prefixlen 64\n";
        assert!(ifconfig_has_address(output, "fe80::1".parse().unwrap()));
        assert!(ifconfig_has_address(output, "fd00::1".parse().unwrap()));
        assert!(!ifconfig_has_address(output, "fd00::10".parse().unwrap()));
        assert!(!ifconfig_has_address(output, "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn unsupported_queue_counts_fail_without_kernel_access() {
        for count in [0, 2, 8] {
            assert!(ZprTun::new_mq(None, count, Some("fd00::1".parse().unwrap())).is_err());
        }
        assert!(ZprTun::new_mq(None, 1, None).is_err());
    }

    #[test]
    fn prefix_lengths_are_bounded() {
        assert!(validate_prefix(0).is_ok());
        assert!(validate_prefix(128).is_ok());
        assert!(validate_prefix(129).is_err());
        assert!(validate_prefix(255).is_err());
    }

    #[test]
    #[ignore = "requires explicit ZPR_MACOS_UTUN_SMOKE=1 and administrator authorization"]
    fn privileged_utun_lifecycle_smoke() {
        assert_eq!(
            std::env::var("ZPR_MACOS_UTUN_SMOKE").as_deref(),
            Ok("1"),
            "use the explicit macOS smoke-test runner"
        );
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "administrator rights required"
        );
        for _ in 0..2 {
            smoke_cycle().expect("isolated utun lifecycle failed");
        }
    }

    fn smoke_cycle() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        fn require(condition: bool, message: &str) -> std::io::Result<()> {
            if condition {
                Ok(())
            } else {
                Err(std::io::Error::other(message))
            }
        }

        fn require_single_host_alias(name: &str, address: IpAddr) -> std::io::Result<()> {
            let output = Command::new(COMMAND_IFCONFIG).arg(name).output()?;
            require(output.status.success(), "cannot inspect IPv6 alias prefix")?;
            let text = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<_> = text
                .lines()
                .filter(|line| ifconfig_has_address(line, address))
                .collect();
            require(lines.len() == 1, "IPv6 alias missing or duplicated")?;
            let fields: Vec<_> = lines[0].split_whitespace().collect();
            require(
                fields.windows(2).any(|pair| pair == ["prefixlen", "128"]),
                "test IPv6 alias must have exactly a /128 prefix",
            )
        }

        fn require_mtu(name: &str, mtu: u16) -> std::io::Result<()> {
            let output = Command::new(COMMAND_IFCONFIG).arg(name).output()?;
            require(
                output.status.success(),
                "temporary interface cannot be inspected",
            )?;
            let text = String::from_utf8_lossy(&output.stdout);
            require(
                text.lines()
                    .next()
                    .is_some_and(|line| line.ends_with(&format!("mtu {mtu}"))),
                "MTU differs from requested value",
            )
        }

        let before = Command::new(COMMAND_IFCONFIG).arg("-l").output()?;
        require(
            before.status.success(),
            "could not snapshot existing interfaces",
        )?;
        let interfaces = String::from_utf8(before.stdout)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let first = IpAddr::V6(std::net::Ipv6Addr::new(
            0xfd97,
            (nonce >> 48) as u16,
            (nonce >> 32) as u16,
            (nonce >> 16) as u16,
            nonce as u16,
            0,
            0,
            1,
        ));
        let mut second = match first {
            IpAddr::V6(value) => value.segments(),
            _ => unreachable!(),
        };
        second[7] = 2;
        let second = IpAddr::V6(second.into());
        let all = Command::new(COMMAND_IFCONFIG).output()?;
        require(
            all.status.success(),
            "could not check test-address conflicts",
        )?;
        let all = String::from_utf8(all.stdout)?;
        require(
            !ifconfig_has_address(&all, first) && !ifconfig_has_address(&all, second),
            "test addresses already exist; no interface was created",
        )?;

        let mut builder = tun::Tun::builder(tun::IPV::V6);
        builder
            .with_address(first)
            .with_prefix_len(128)
            .with_mtu(1400);
        let mut device = ZprTun::new(tun::Tun::create(&builder)?);
        let name = device.name().to_owned();
        let result = (|| -> std::io::Result<()> {
            require(
                name.starts_with("utun") && !interfaces.split_whitespace().any(|old| old == name),
                "kernel did not assign a fresh temporary interface",
            )?;
            require_mtu(&name, 1400)?;
            device
                .inner
                .set_mtu(1280)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            require_mtu(&name, 1280)?;
            require(
                device.has_address(first)?,
                "ioctl-configured IPv6 /128 is absent",
            )?;
            require_single_host_alias(&name, first)?;
            device.add_address(second, 128)?;
            device.add_address(second, 128)?;
            require(device.has_address(second)?, "added IPv6 /128 is absent")?;
            require_single_host_alias(&name, second)?;
            device.clear_address(second, 128)?;
            device.clear_address(second, 128)?;
            require(
                !device.has_address(second)?,
                "removed alias remains present",
            )?;
            device.clear_address(first, 128)?;
            require(
                !device.has_address(first)?,
                "initial IPv6 address remains present",
            )?;
            Ok(())
        })();
        // Always close both kernel descriptors before reporting a lifecycle failure.
        drop(device);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let after = Command::new(COMMAND_IFCONFIG).arg("-l").output()?;
            require(
                after.status.success(),
                "could not verify interface teardown",
            )?;
            if !String::from_utf8_lossy(&after.stdout)
                .split_whitespace()
                .any(|interface| interface == name)
            {
                break;
            }
            require(
                std::time::Instant::now() < deadline,
                "temporary utun remains after descriptor close",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        result?;
        println!(
            "{name}: MTU 1400 then 1280, two IPv6 /128 addresses, idempotent alias lifecycle and descriptor-close teardown passed"
        );
        Ok(())
    }
}
