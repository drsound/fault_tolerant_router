//! DHCPv6 with prefix delegation on provider B (SPEC.md AS-44, FR-CT-5): a
//! kea server that also announces the server-unicast option, at an address
//! outside the uplink's on-link prefix, and the router's DHCPv6 client.
//!
//! The client is dhcpcd, or ISC dhclient where dhcpcd is not installed (the
//! Debian 12 environment): they differ in how they send messages by unicast
//! (dhcpcd leaves the route lookup unbound, dhclient binds it to the
//! interface with a link-local source), which is what AS-44 observes.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::netns;
use crate::plan::{Node, Uplink};
use crate::topology::{Topology, chmod_x};

/// The address at which provider B's DHCPv6 server takes messages sent by
/// unicast, announced in the server-unicast option: inside B's prefix and
/// outside the uplink's on-link /64, so the router reaches it through a
/// default route.
pub const DHCPV6_UNICAST: &str = "2001:db8:b:fffe::1";

/// The pool of the /60 prefixes that provider B delegates.
pub const DELEGATED_POOL: &str = "2001:db8:b:100::/56";

/// Renewal time (T1) of B's DHCPv6 leases, in seconds.
pub const DHCPV6_T1: u64 = 30;

/// Rebinding time (T2) of B's DHCPv6 leases, in seconds.
pub const DHCPV6_T2: u64 = 50;

/// Valid lifetime of B's DHCPv6 leases, in seconds.
pub const DHCPV6_VALID: u64 = 100;

/// The router's DHCPv6 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dhcpv6Client {
    Dhcpcd,
    Dhclient,
}

impl Dhcpv6Client {
    /// `FTR_TEST_DHCPV6_CLIENT` (`dhcpcd` or `dhclient`); otherwise dhcpcd
    /// when installed, ISC dhclient when not.
    pub fn detect() -> Result<Dhcpv6Client> {
        match std::env::var("FTR_TEST_DHCPV6_CLIENT").as_deref() {
            Ok("dhcpcd") => return Ok(Dhcpv6Client::Dhcpcd),
            Ok("dhclient") => return Ok(Dhcpv6Client::Dhclient),
            Ok(other) => bail!("FTR_TEST_DHCPV6_CLIENT={other}: expected dhcpcd or dhclient"),
            Err(_) => {}
        }
        if installed("dhcpcd")? {
            Ok(Dhcpv6Client::Dhcpcd)
        } else if installed("dhclient")? {
            Ok(Dhcpv6Client::Dhclient)
        } else {
            bail!("no DHCPv6 client: install dhcpcd or ISC dhclient")
        }
    }
}

/// Path of an installed program, as the shell finds it.
fn which(program: &str) -> Result<String> {
    Ok(netns::host("sh", ["-c", &format!("command -v {program} || true")])?
        .trim()
        .to_owned())
}

fn installed(program: &str) -> Result<bool> {
    Ok(!which(program)?.is_empty())
}

impl Topology {
    /// A copy of an installed program in the run's executable directory:
    /// the distributions confine kea-dhcp6 and dhclient by their paths
    /// (AppArmor), which keeps them out of the run directory.
    fn unconfined(&self, program: &str) -> Result<PathBuf> {
        let src = which(program)?;
        if src.is_empty() {
            bail!("{program} is not installed");
        }
        let bin = self.exec_dir()?.join(program);
        fs::copy(&src, &bin).with_context(|| format!("copying {src}"))?;
        Ok(bin)
    }

    /// Starts kea-dhcp6 on provider B: addresses of 2001:db8:b:ffff::/64
    /// (IA_NA) and /60 prefixes of [`DELEGATED_POOL`] (IA_PD), with the
    /// lease times above and the server-unicast option for
    /// [`DHCPV6_UNICAST`], sent whether or not the client asks for it.
    pub fn start_dhcpv6_server(&self) -> Result<()> {
        let ns = self.ns(Node::IspB);
        ns.ip(&format!("addr add {DHCPV6_UNICAST}/128 dev wan nodad"))?;
        let bin = self.unconfined("kea-dhcp6")?;
        let conf = self.dir().join("kea-dhcp6.json");
        fs::write(&conf, kea_config())?;
        let log = self.dir().join("kea-dhcp6.log");
        let env = [
            ("KEA_LOCKFILE_DIR".to_owned(), "none".to_owned()),
            ("KEA_PIDFILE_DIR".to_owned(), self.dir().display().to_string()),
        ];
        ns.spawn_env(&bin.to_string_lossy(), ["-c", &conf.to_string_lossy()], &env, &log)?;
        self.wait_for("kea-dhcp6 to start", Duration::from_secs(10), || {
            let text = fs::read_to_string(&log).unwrap_or_default();
            if text.contains("DHCP6_INIT_FAIL") || text.contains("DHCPSRV_NO_SOCKETS_OPEN") {
                bail!("kea-dhcp6 failed:\n{text}");
            }
            Ok(text.contains("DHCP6_STARTED"))
        })?;
        Ok(())
    }

    /// Starts the router's DHCPv6 client on B's uplink, asking for an
    /// address and a delegated prefix whose first /64 it assigns to `lan`,
    /// as a router's operating system does.
    pub fn start_dhcpv6_client(&self, client: Dhcpv6Client) -> Result<()> {
        let ifc = Uplink::B.carrier_iface();
        let r = self.router();
        // Both clients send from the link-local address; dhclient gives up
        // without one.
        self.wait_for(
            &format!("a link-local address on {ifc}"),
            Duration::from_secs(10),
            || {
                Ok(!r
                    .ip(&format!("-6 addr show dev {ifc} scope link -tentative"))?
                    .trim()
                    .is_empty())
            },
        )?;
        let d = self.dir();
        let log = d.join(format!("dhcpv6-{ifc}.log"));
        match client {
            Dhcpv6Client::Dhcpcd => {
                // Manager mode: dhcpcd ignores the server-unicast option
                // otherwise. No hook scripts (they would edit the host's
                // resolver configuration).
                let conf = d.join("dhcpcd.conf");
                fs::write(
                    &conf,
                    format!(
                        "allowinterfaces {ifc} lan\nipv6only\nnoipv6rs\nscript /bin/true\nduid\ninterface {ifc}\n  ia_na 1\n  ia_pd 2 lan/0/64\n"
                    ),
                )?;
                // Its run and database directories are fixed: private copies
                // in the mount namespace of `ip netns exec`, so that the runs
                // of a host do not share them.
                let cmd = format!(
                    "for d in /run/dhcpcd /var/lib/dhcpcd; do mkdir -p $d && mount -t tmpfs tmpfs $d || exit 1; done; exec dhcpcd -6 -M -B -d -f {}",
                    conf.display()
                );
                r.spawn("sh", ["-c", &cmd], &log)?;
            }
            Dhcpv6Client::Dhclient => {
                let script = d.join("dhclient-script");
                fs::write(&script, dhclient_script())?;
                chmod_x(&script)?;
                let path = |name: &str| d.join(name).display().to_string();
                r.spawn(
                    &self.unconfined("dhclient")?.to_string_lossy(),
                    [
                        "-6",
                        "-N",
                        "-P",
                        "-d",
                        "-v",
                        "-sf",
                        &path("dhclient-script"),
                        "-pf",
                        &path("dhclient6.pid"),
                        "-lf",
                        &path("dhclient6.leases"),
                        ifc,
                    ],
                    &log,
                )?;
            }
        }
        Ok(())
    }
}

fn kea_config() -> String {
    format!(
        r#"{{ "Dhcp6": {{
  "interfaces-config": {{
    "interfaces": [ "wan/{DHCPV6_UNICAST}" ],
    "service-sockets-max-retries": 50, "service-sockets-retry-wait-time": 100 }},
  "lease-database": {{ "type": "memfile", "persist": false }},
  "server-id": {{ "type": "LL", "persist": false }},
  "renew-timer": {DHCPV6_T1}, "rebind-timer": {DHCPV6_T2},
  "preferred-lifetime": {DHCPV6_VALID}, "valid-lifetime": {DHCPV6_VALID},
  "option-data": [ {{ "name": "unicast", "data": "{DHCPV6_UNICAST}", "always-send": true }} ],
  "subnet6": [ {{ "id": 1, "subnet": "2001:db8:b:ffff::/64", "interface": "wan",
    "pools": [ {{ "pool": "2001:db8:b:ffff::1000-2001:db8:b:ffff::1fff" }} ],
    "pd-pools": [ {{ "prefix": "2001:db8:b:100::", "prefix-len": 56, "delegated-len": 60 }} ] }} ],
  "loggers": [ {{ "name": "kea-dhcp6", "output_options": [ {{ "output": "stdout" }} ], "severity": "INFO" }} ]
}} }}
"#
    )
}

/// What a distribution's dhclient script does with a DHCPv6 lease on a
/// router: the address on the uplink, the first /64 of the delegated
/// prefix on the LAN. Nothing else (no resolver configuration).
fn dhclient_script() -> &'static str {
    r#"#!/bin/sh
# ftr-testbed dhclient script for DHCPv6 with prefix delegation.
case "$reason" in
  BOUND6|RENEW6|REBIND6|REBOOT6)
    life="valid_lft ${new_max_life:-forever} preferred_lft ${new_preferred_life:-forever}"
    [ -n "$new_ip6_address" ] && ip -6 addr replace "$new_ip6_address/128" dev "$interface" $life
    # The delegated prefixes are /60s ending in "::".
    [ -n "$new_ip6_prefix" ] && ip -6 addr replace "${new_ip6_prefix%/*}1/64" dev lan $life
    ;;
esac
exit 0
"#
}
