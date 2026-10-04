//! Prober against the running kernel: a peer namespace answers ICMP echo and
//! resets TCP connections. Run as root under `unshare -n` (see
//! kernel_netlink.rs).

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use polywan::config::Target;
use polywan::model::{Family, FieldValue, FwMask, PathKey, UplinkId};
use polywan::probe::{self, Report, Spec};
use tokio::sync::mpsc;

mod common;
use common::{private_netns, sh};

/// A peer namespace on the other end of veth `p0`, with the targets on its
/// loopback interface.
struct Peer(Child);

impl Peer {
    fn start() -> Peer {
        let _ = Command::new("ip")
            .args(["link", "del", "p0"])
            .stderr(Stdio::null())
            .status();
        let child = Command::new("unshare")
            .args(["-n", "sleep", "120"])
            .spawn()
            .expect("unshare");
        std::thread::sleep(Duration::from_millis(200));
        let pid = child.id();
        let peer = |c: &str| sh(&format!("nsenter -t {pid} -n sh -c '{c}'"));
        sh(&format!(
            "ip link set lo up && ip link add p0 type veth peer name p1 && ip link set p1 netns {pid}"
        ));
        sh("ip addr add 192.0.2.2/24 dev p0 && ip addr add 2001:db8::2/64 dev p0 nodad && ip link set p0 up");
        peer("ip link set lo up && ip addr add 198.18.0.1/32 dev lo && ip addr add 2001:db8:ff::1/128 dev lo");
        peer("ip addr add 192.0.2.1/24 dev p1 && ip addr add 2001:db8::1/64 dev p1 nodad && ip link set p1 up");
        // Probe-marked traffic of uplink 1 uses its path table (FR-ROUTE-3).
        sh("ip rule add fwmark 0x410000/0xff0000 lookup 1001 priority 1001");
        sh("ip -6 rule add fwmark 0x410000/0xff0000 lookup 1001 priority 1001");
        // Probe replies are unmarked: with rp_filter (inherited from the
        // host on some distributions) their reverse-path check needs the
        // source rule of the probe source (FR-SYS-2).
        sh("ip rule add from 192.0.2.2 lookup 1001 priority 1501");
        sh("ip route add default via 192.0.2.1 dev p0 table 1001");
        sh("ip -6 route add default via 2001:db8::1 dev p0 table 1001");
        Peer(child)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = Command::new("ip").args(["rule", "del", "priority", "1001"]).status();
        let _ = Command::new("ip")
            .args(["-6", "rule", "del", "priority", "1001"])
            .status();
    }
}

fn spec(family: Family, targets: &[&str], run_to_completion: bool) -> Spec {
    let id = UplinkId::new(1).unwrap();
    let source: IpAddr = if family == Family::V4 {
        "192.0.2.2"
    } else {
        "2001:db8::2"
    }
    .parse()
    .unwrap();
    Spec {
        path: PathKey { uplink: id, family },
        generation: 7,
        interface: "p0".into(),
        ifindex: 0,
        source,
        mark: FwMask::DEFAULT.encode(FieldValue::probe(id)),
        targets: targets
            .iter()
            .map(|t| polywan::config::parse_target(t).unwrap())
            .collect(),
        interval: Duration::from_secs(1),
        timeout: Duration::from_millis(300),
        attempts: 2,
        required_reachable: 2,
        run_to_completion,
    }
}

async fn one_round(s: Spec) -> probe::RoundReport {
    let (tx, mut rx) = mpsc::channel(4);
    let task = probe::spawn(s, tx);
    let r = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a round")
        .expect("a report");
    task.abort();
    match r {
        Report::Round(r) => r,
        Report::Failed(e) => panic!("prober failed: {:?}", e.error),
    }
}

#[tokio::test]
#[ignore = "needs root in a private network namespace"]
async fn rounds_validate_replies_and_cancel_open_attempts() {
    private_netns();
    let _peer = Peer::start();
    for (family, up, tcp, down) in [
        (Family::V4, "icmp:198.18.0.1", "tcp:198.18.0.1:9", "icmp:198.18.0.2"),
        (
            Family::V6,
            "icmp:2001:db8:ff::1",
            "tcp:[2001:db8:ff::1]:9",
            "icmp:2001:db8:ff::2",
        ),
    ] {
        // Early end: the unreachable target's open attempt is canceled.
        let r = one_round(spec(family, &[up, tcp, down], false)).await;
        assert_eq!(r.generation, 7);
        assert!(r.passed, "{family}: {r:?}");
        assert_eq!(r.reachable, 2);
        let replied: Vec<Target> = r.samples.iter().filter(|s| s.rtt.is_some()).map(|s| s.target).collect();
        assert_eq!(replied.len(), 2, "{family}: ICMP reply and TCP RST: {r:?}");
        assert!(r.canceled >= 1, "{family}: {r:?}");
        // Run to completion (quality gates): every attempt is a sample.
        let r = one_round(spec(family, &[up, tcp, down], true)).await;
        assert!(r.passed);
        assert_eq!(r.canceled, 0, "{family}: {r:?}");
        assert_eq!(
            r.samples.iter().filter(|s| s.rtt.is_none()).count(),
            2,
            "{family}: two lost attempts"
        );
        // A failing round: one reachable target out of two required.
        let r = one_round(spec(family, &[up, down], false)).await;
        assert!(!r.passed, "{family}: {r:?}");
    }
}
