use crate::sys::ZprTun;
use std::io::Result;
use std::net::IpAddr;
use std::sync::Arc;

/// This interface provides shared access to the TUN device for controlling
/// its state.  Its API is limited to restrict coupling of the full system
/// with the TUN device.
pub trait TunCtl: Sync {
    /// Inform the kernel's networking layer whether a carrier is present.
    /// (I.e. whether we are passing packets.)  This is reflected on the
    /// interface itself and is used by the kernel to make routing decisions.
    fn set_carrier(&self, carrier: bool) -> Result<()>;

    /// Adds an IP address of the TUN device.
    fn add_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()>;

    /// Clear an IP address from the TUN device.  Does not error if address is not set to begin with.
    fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()>;
}

/// Canonical implementation of the `TunCtl` interface, just a thin wrapper
/// around a reference to a `ZprTun` struct.
pub struct TunCtlImpl {
    tun: Arc<ZprTun>,
    route_table: Option<u32>,
    route_lock: std::sync::Mutex<()>,
}

impl TunCtlImpl {
    pub fn new(tun: Arc<ZprTun>) -> Self {
        Self {
            tun,
            route_table: None,
            route_lock: std::sync::Mutex::new(()),
        }
    }

    pub fn with_route_table(mut self, route_table: Option<u32>) -> Self {
        self.route_table = route_table;
        self
    }

    fn update_source_route(&self, address: IpAddr, install: bool) -> Result<()> {
        let Some(table) = self.route_table else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        {
            update_source_route(self.tun.name(), table, address, install, |args| {
                let output = std::process::Command::new("/usr/sbin/ip")
                    .args(args)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "TUN source routing command {args:?} failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                Ok(String::from_utf8_lossy(&output.stdout).into_owned())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (table, address, install);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN source routing requires Linux",
            ))
        }
    }
}

impl TunCtl for TunCtlImpl {
    fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
    fn add_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        let _guard = self
            .route_lock
            .lock()
            .map_err(|_| std::io::Error::other("TUN source routing mutex poisoned"))?;
        self.tun.add_address(addr, prefix_len)?;
        self.update_source_route(addr, true)
    }
    fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        let _guard = self
            .route_lock
            .lock()
            .map_err(|_| std::io::Error::other("TUN source routing mutex poisoned"))?;
        self.update_source_route(addr, false)?;
        self.tun.clear_address(addr, prefix_len)
    }
}

#[cfg(any(target_os = "linux", test))]
fn update_source_route(
    interface: &str,
    table: u32,
    address: IpAddr,
    install: bool,
    mut run: impl FnMut(&[String]) -> Result<String>,
) -> Result<()> {
    if !address.is_ipv6() || !(1..=252).contains(&table) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN source routing requires IPv6 and a dedicated table in 1-252",
        ));
    }
    let source = format!("{address}/128");
    let priority = (10_000 + table).to_string();
    let table = table.to_string();
    let selector = [
        "pref",
        priority.as_str(),
        "from",
        source.as_str(),
        "lookup",
        table.as_str(),
    ];
    let args = |prefix: &[&str]| {
        prefix
            .iter()
            .chain(selector.iter())
            .map(|arg| arg.to_string())
            .collect::<Vec<_>>()
    };
    if install {
        run(&[
            "-6", "route", "replace", "default", "dev", interface, "table", &table,
        ]
        .map(String::from))?;
    }
    let exists = !run(&args(&["-6", "rule", "show"]))?.trim().is_empty();
    if install != exists {
        run(&args(&["-6", "rule", if install { "add" } else { "del" }]))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_routing_configuration_is_explicit_and_reserved_tables_are_rejected() {
        use clap::Parser;
        assert_eq!(crate::config::Config::default().tun_route_table, None);
        let control = crate::main_args::Control::try_parse_from([
            "ph",
            "adapter",
            "--tun-route-table",
            "103",
        ])
        .unwrap();
        let crate::main_args::Command::Adapter { common, .. } = control.command else {
            panic!("expected adapter");
        };
        let config = crate::config::Config::new_for_adapter(None, &common).unwrap();
        assert_eq!(config.tun_route_table, Some(103));
        let global: crate::config::GlobalConfigSection =
            toml::from_str("tun_route_table = 100").unwrap();
        assert_eq!(global.tun_route_table, Some(100));
        for value in ["0", "253", "254", "255", "4294967295"] {
            assert!(
                crate::main_args::Control::try_parse_from([
                    "ph",
                    "adapter",
                    "--tun-route-table",
                    value,
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn source_routing_owns_only_exact_addresses_and_is_idempotent() {
        let address = "fd5a:5052:0:aaa::123".parse().unwrap();
        for (install, exists, count) in [
            (true, false, 3),
            (true, true, 2),
            (false, true, 2),
            (false, false, 1),
        ] {
            let mut commands = Vec::new();
            update_source_route("tun3", 103, address, install, |args| {
                commands.push(args.join(" "));
                Ok(
                    if args.get(2).map(String::as_str) == Some("show") && exists {
                        "10103: from fd5a:5052:0:aaa::123 lookup 103".into()
                    } else {
                        String::new()
                    },
                )
            })
            .unwrap();
            assert_eq!(commands.len(), count);
            assert!(
                commands.iter().any(|args| args
                    == "-6 rule show pref 10103 from fd5a:5052:0:aaa::123/128 lookup 103")
            );
            if install {
                assert_eq!(commands[0], "-6 route replace default dev tun3 table 103");
            }
            assert!(!commands.iter().any(|args| args.contains("flush")));
        }
    }

    #[test]
    fn source_routing_rejects_reserved_tables_and_propagates_kernel_errors() {
        for table in [0, 253, 254, 255, u32::MAX] {
            assert!(
                update_source_route("tun0", table, "::1".parse().unwrap(), true, |_| {
                    panic!("invalid route table reached kernel")
                })
                .is_err()
            );
        }
        assert!(
            update_source_route("tun0", 100, "::1".parse().unwrap(), true, |_| {
                Err(std::io::Error::other("kernel rejected route"))
            })
            .is_err()
        );
    }
}
