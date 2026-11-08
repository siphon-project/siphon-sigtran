use siphon_sigtran::config::Config;

fn parse(extra: &str) -> Config {
    Config::parse(&format!("node: {{ point_code: 1000, variant: ITU }}\nassociations:\n  - {{ id: peer, adaptation: m3ua, role: client, addrs: [peer.example], port: 2905{extra} }}\n")).unwrap()
}

#[test]
fn dns_defaults_and_overrides() {
    let config = parse("");
    let a = &config.associations[0];
    assert!(!a.all_addresses);
    assert_eq!(a.resolve_seconds, 30);
    assert_eq!(a.reconnect_max_seconds, 30);
    let config = parse(", all_addresses: true, resolve_seconds: 5, reconnect_max_seconds: 8");
    let a = &config.associations[0];
    assert!(a.all_addresses);
    assert_eq!(a.resolve_seconds, 5);
    assert_eq!(a.reconnect_max_seconds, 8);
}

#[test]
fn invalid_dns_groups_are_rejected() {
    for keys in [
        "role: server, addrs: [192.0.2.1], all_addresses: true",
        "role: client, addrs: [a.example, b.example], all_addresses: true",
        "role: client, addrs: [a.example], resolve_seconds: 0",
        "role: client, addrs: [a.example], reconnect_max_seconds: 0",
    ] {
        let yaml = format!("node: {{ point_code: 1000, variant: ITU }}\nassociations:\n  - {{ id: peer, adaptation: m3ua, port: 2905, {keys} }}\n");
        assert!(Config::parse(&yaml).is_err(), "{keys}");
    }
}

#[test]
fn configured_ids_cannot_shadow_generated_members() {
    let yaml = "node: { point_code: 1000, variant: ITU }\nassociations:\n  - { id: peer, adaptation: m3ua, role: client, addrs: [peer.example], port: 2905, all_addresses: true }\n  - { id: 'peer@192.0.2.1:2905', adaptation: m3ua, role: client, addrs: [192.0.2.1], port: 2905 }\n";
    assert!(Config::parse(yaml).is_err());
    assert!(Config::parse(&yaml.replace("all_addresses: true", "all_addresses: false")).is_ok());
}
