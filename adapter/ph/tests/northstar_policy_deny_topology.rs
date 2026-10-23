use std::net::Ipv6Addr;
use std::path::PathBuf;

#[test]
fn northstar_machine_policy_deny_topology_maps_only_synthetic_machine_01() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../examples/northstar-policy-deny-lab/northstar-machine-policy-deny-topology.zplc",
    );
    let source = std::fs::read_to_string(&fixture).expect("read Northstar topology fixture");
    assert!(source.contains("SYNTHETIC LAB ONLY"));

    let config: toml::Value = toml::from_str(&source).expect("parse Northstar topology TOML");
    let nodes = config["nodes"].as_table().expect("nodes table");
    assert_eq!(
        nodes.len(),
        2,
        "only the source and synthetic service are nodes"
    );
    assert!(
        source.contains("machine-01 alone is active/provisioned"),
        "synthetic fixture mapping and active-member constraint must be documented"
    );
    assert!(
        source.contains("runtime/northstar-synthetic/scenarios/")
            && source.contains(
                "machine-policy-deny.json (organization_id=northstar, id=machine-policy-deny)"
            ),
        "handoff must use the existing scenario package identity"
    );
    let client = &nodes["machine_01_finance_client"];
    let workspace = &nodes["northstar_finance_workspace"];
    assert_eq!(
        client["zpr_address"].as_str(),
        Some("fd00:5a17:2026:104::1")
    );
    assert_eq!(workspace["zpr_address"].as_str(), Some("fd00:1:2::1"));
    for address in [
        client["zpr_address"].as_str().expect("client ZPR address"),
        workspace["zpr_address"]
            .as_str()
            .expect("workspace ZPR address"),
    ] {
        let address: Ipv6Addr = address.parse().expect("valid IPv6 fixture address");
        assert_eq!(
            address.segments()[0] & 0xfe00,
            0xfc00,
            "address must be ULA"
        );
    }
    assert_ne!(
        client["zpr_address"].as_str(),
        Some("fd00:1:4::1"),
        "do not pin the profile's guessed source address"
    );
    let hosts = config["resolver"]["hosts"]
        .as_table()
        .expect("host resolver");
    assert_eq!(
        hosts["finance-client"].as_str(),
        client["zpr_address"].as_str()
    );
    assert_eq!(
        hosts["finance-workspace"].as_str(),
        workspace["zpr_address"].as_str()
    );

    let client_provider = client["provider"][0]
        .as_array()
        .expect("finance-client provider mapping");
    assert_eq!(client_provider[0].as_str(), Some("device.zpr.adapter.cn"));
    assert_eq!(client_provider[1].as_str(), Some("finance-client"));

    let service = &config["services"]["FinanceWorkspace"];
    assert_eq!(service["protocol"].as_str(), Some("icmpv6_echo_request"));
    let service_provider = service["provider"][0]
        .as_array()
        .expect("FinanceWorkspace provider mapping");
    assert_eq!(service_provider[1].as_str(), Some("finance-workspace"));
    let protocol = &config["protocols"]["icmpv6_echo_request"];
    assert_eq!(protocol["l4protocol"].as_str(), Some("iana.ICMP6"));
    assert_eq!(protocol["icmp_type"].as_str(), Some("oneshot"));
    assert_eq!(protocol["icmp_codes"][0].as_integer(), Some(128));

    let peers = config["links"]["finance-to-workspace"]["peers"]
        .as_array()
        .expect("source-to-destination link");
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0]["node"].as_str(), Some("machine_01_finance_client"));
    assert_eq!(
        peers[1]["node"].as_str(),
        Some("northstar_finance_workspace")
    );
}
