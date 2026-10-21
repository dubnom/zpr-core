use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

pub const WINDOWS_PROFILE_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum WindowsProfileError {
    #[error("invalid Windows preflight profile TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported Windows preflight profile version {0}")]
    UnsupportedVersion(u32),
    #[error("global.tun_if must name an existing Wintun adapter")]
    MissingTunInterface,
    #[error("global.zpr_addr must contain at least one ZPR address")]
    MissingZprAddress,
    #[error("adapter.name must not be blank when provided")]
    BlankAdapterName,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsProfile {
    pub profile_version: u32,
    pub global: WindowsProfileGlobal,
    pub adapter: WindowsProfileAdapter,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsProfileGlobal {
    pub tun_if: String,
    pub zpr_addr: Vec<IpAddr>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsProfileAdapter {
    pub node_addr: SocketAddr,
    pub name: Option<String>,
}

pub fn parse_windows_profile(input: &str) -> Result<WindowsProfile, WindowsProfileError> {
    let profile: WindowsProfile = toml::from_str(input)?;
    validate_windows_profile(&profile)?;
    Ok(profile)
}

fn validate_windows_profile(profile: &WindowsProfile) -> Result<(), WindowsProfileError> {
    if profile.profile_version != WINDOWS_PROFILE_VERSION {
        return Err(WindowsProfileError::UnsupportedVersion(
            profile.profile_version,
        ));
    }
    if profile.global.tun_if.trim().is_empty() || profile.global.tun_if.contains('\0') {
        return Err(WindowsProfileError::MissingTunInterface);
    }
    if profile.global.zpr_addr.is_empty() {
        return Err(WindowsProfileError::MissingZprAddress);
    }
    if profile
        .adapter
        .name
        .as_ref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(WindowsProfileError::BlankAdapterName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        WINDOWS_PROFILE_VERSION, WindowsProfileError, parse_windows_profile,
        validate_windows_profile,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const VALID_PROFILE: &str = r#"
profile_version = 1

[global]
tun_if = "ZPR Demo"
zpr_addr = ["fd00::10"]

[adapter]
node_addr = "192.0.2.10:5000"
name = "demo-endpoint"
"#;

    #[test]
    fn parses_supported_preflight_profile() {
        let profile = parse_windows_profile(VALID_PROFILE).unwrap();

        assert_eq!(profile.profile_version, WINDOWS_PROFILE_VERSION);
        assert_eq!(profile.global.tun_if, "ZPR Demo");
        assert_eq!(
            profile.global.zpr_addr,
            [IpAddr::V6("fd00::10".parse().unwrap())]
        );
        assert_eq!(
            profile.adapter.node_addr,
            "192.0.2.10:5000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(profile.adapter.name.as_deref(), Some("demo-endpoint"));
    }

    #[test]
    fn adapter_name_is_optional() {
        let input = VALID_PROFILE.replace("name = \"demo-endpoint\"", "");

        assert!(parse_windows_profile(&input).is_ok());
    }

    #[test]
    fn rejects_unsupported_profile_version() {
        let input = VALID_PROFILE.replace("profile_version = 1", "profile_version = 2");

        assert!(matches!(
            parse_windows_profile(&input),
            Err(WindowsProfileError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_blank_or_nul_interface_names() {
        for name in ["", "   "] {
            let input = VALID_PROFILE.replace("ZPR Demo", name);
            assert!(matches!(
                parse_windows_profile(&input),
                Err(WindowsProfileError::MissingTunInterface)
            ));
        }

        let mut profile = parse_windows_profile(VALID_PROFILE).unwrap();
        profile.global.tun_if = "bad\0name".into();
        assert!(matches!(
            validate_windows_profile(&profile),
            Err(WindowsProfileError::MissingTunInterface)
        ));
    }

    #[test]
    fn rejects_empty_zpr_address_list() {
        let input = VALID_PROFILE.replace("zpr_addr = [\"fd00::10\"]", "zpr_addr = []");

        assert!(matches!(
            parse_windows_profile(&input),
            Err(WindowsProfileError::MissingZprAddress)
        ));
    }

    #[test]
    fn rejects_blank_adapter_name() {
        let input = VALID_PROFILE.replace("demo-endpoint", "  ");

        assert!(matches!(
            parse_windows_profile(&input),
            Err(WindowsProfileError::BlankAdapterName)
        ));
    }

    #[test]
    fn rejects_unrecognized_runtime_or_network_fields() {
        for extra in [
            "routes = [\"0.0.0.0/0\"]",
            "dns = \"192.0.2.53\"",
            "private_key_file = \"identity.pem\"",
            "private_key_data = \"not-accepted\"",
            "dll_path = \"C:/wintun.dll\"",
        ] {
            let input = VALID_PROFILE.replace("[global]", &format!("[global]\n{extra}"));
            assert!(parse_windows_profile(&input).is_err(), "accepted {extra}");
        }
    }

    #[test]
    fn rejects_malformed_addresses() {
        let invalid_node = VALID_PROFILE.replace("192.0.2.10:5000", "not-an-address");
        assert!(parse_windows_profile(&invalid_node).is_err());

        let invalid_zpr = VALID_PROFILE.replace("fd00::10", "not-an-ip");
        assert!(parse_windows_profile(&invalid_zpr).is_err());
    }

    #[test]
    fn supports_ipv4_zpr_address() {
        let input = VALID_PROFILE.replace(
            "fd00::10",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))
                .to_string()
                .as_str(),
        );

        assert_eq!(
            parse_windows_profile(&input).unwrap().global.zpr_addr,
            [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))]
        );
    }
}
