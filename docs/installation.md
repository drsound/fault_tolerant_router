# Installation

## Requirements

- Linux 6.1 or later; the daemon refuses to start on older kernels.
- nftables 1.0.6 or later, for the default managed firewall mode.
- x86_64, aarch64 or armv7 (for example a Raspberry Pi with a 64-bit or a 32-bit system).
- Root: PolyWAN runs as root, confined by the sandbox of its systemd unit. It does not run as another user.
- systemd is the supported service manager, but not required: without it, PolyWAN runs in the foreground and logs to standard error.
- The router's interfaces, addresses, DHCP, PPP and Router Advertisement clients configured by the operating system (systemd-networkd, NetworkManager, ifupdown, pppd): PolyWAN observes them, it does not configure them. The [recipes](recipes/) show how for common setups.

PolyWAN 2.0 was tested on Debian 12 (Linux 6.1, nftables 1.0.6, systemd 252), Debian 13 (systemd 257), Ubuntu 26.04 and Debian 13 on a Raspberry Pi 4, with the acceptance suite running under the packaged unit.

## Release files

Every release on the [releases page](https://github.com/drsound/polywan/releases) has:

| File | What |
|---|---|
| `polywan_VERSION-1_amd64.deb`, `_arm64.deb`, `_armhf.deb` | Debian and Ubuntu packages |
| `polywan-x86_64-unknown-linux-musl`, `polywan-aarch64-unknown-linux-musl`, `polywan-armv7-unknown-linux-musleabihf` | static binaries, for any distribution |
| `SHA256SUMS` | the checksums of every file |
| `THIRD-PARTY-LICENSES`, `rust-std-copyright.html` | the licenses of the code linked into the binaries |
| `PROVENANCE.txt` | the source commit and the toolchain of the build |

Every file is signed with a GitHub artifact attestation, which proves that it was built by this repository's release workflow. To verify a download, with the [GitHub CLI](https://cli.github.com/):

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify polywan_2.0.0-1_amd64.deb --repo drsound/polywan
```

## From the Debian package

```sh
apt install ./polywan_2.0.0-1_amd64.deb
```

The package installs:

- `/usr/bin/polywan`, the man page `polywan(8)` and completions for bash, zsh and fish;
- the unit `polywan.service`, neither enabled nor started;
- the group `polywan` (through `systemd-sysusers`), with no members: its members control the daemon (see [API](api.md#who-can-do-what));
- the example configuration `/usr/share/doc/polywan/examples/config.toml`, not an active configuration.

It depends on `nftables` and suggests `msmtp`, for [email](email.md).

Then:

1. Write the configuration, starting from the example:

   ```sh
   install -D -m 0600 /usr/share/doc/polywan/examples/config.toml /etc/polywan/config.toml
   ```

   Edit it: the interfaces of your downlinks and uplinks, their ids, names, priorities and weights, and NAT (see the [configuration reference](configuration.md) and the [recipes](recipes/)). The file and its directories must belong to root and not be writable by others.
2. If systemd-networkd manages the router's interfaces, disable its management of foreign rules and routes, or PolyWAN refuses to start (see the [systemd-networkd recipe](recipes/systemd-networkd.md)).
3. Check the configuration and the system:

   ```sh
   polywan check-config
   ```

   It reports errors (the daemon would refuse to start) and warnings (things to know about).
4. Optionally, see what PolyWAN would do: `polywan export-nft` prints its nftables table, and `polywan run --dry-run` computes every routing change once, logs it and exits without applying anything.
5. Start it, now and at every boot:

   ```sh
   systemctl enable --now polywan
   polywan status
   ```

`systemctl start` returns once PolyWAN has opened its sockets and made its first attempt to install its routing, successful or not. That the service is running, or that a reload succeeded, says nothing about the uplinks' health: `polywan status` does. If the configuration is refused, the service fails with exit status 78 and systemd does not restart it until you start it again; other failures are restarted after 5 seconds. See [troubleshooting](troubleshooting.md#the-daemon-does-not-start).

Membership of `polywan` is needed for `drain`, `undrain`, `reload` and `notify-test`; `status` and `events` work for every local user unless you restrict them (see [API](api.md)).

## From the static binary

For distributions without Debian packages, or to install by hand:

```sh
install -m 0755 polywan-x86_64-unknown-linux-musl /usr/bin/polywan
groupadd --system polywan
mkdir -p /etc/polywan
polywan generate-config > /etc/polywan/config.toml
chmod 0600 /etc/polywan/config.toml
```

`polywan generate-config` prints the same example the package installs. For systemd, install the unit from the source of the same release, unchanged:

```sh
curl -fsSL -o /etc/systemd/system/polywan.service \
  https://raw.githubusercontent.com/drsound/polywan/v2.0.0/packaging/polywan.service
systemctl daemon-reload
```

The unit expects the binary at `/usr/bin/polywan`; elsewhere, replace `ExecStart=` and `ExecReload=` in a drop-in as shown [below](#changing-the-unit). Then continue from step 2 of the package installation. The state and runtime directories (`/var/lib/polywan`, `/run/polywan`) are created by the unit, or by the daemon itself without systemd.

To upgrade, replace the binary and restart the service. To uninstall, follow [removing PolyWAN](#removing-polywan), then delete the binary, the unit, the group and `/etc/polywan`.

## From crates.io

With a Rust toolchain (1.89 or later), `cargo install polywan` builds the latest release for the machine it runs on. That binary uses the system's C library rather than musl, so account lookups also go through the system's name services. Install it as `/usr/bin/polywan` (`install -m 0755 ~/.cargo/bin/polywan /usr/bin/polywan`) and continue as for the static binary above.

## Without systemd

`polywan run` runs the daemon in the foreground, logging to standard error; it creates `/var/lib/polywan` and `/run/polywan` if they are missing. Under another service manager, run it as root, restart it when it exits with a status other than 0 and 78, and send SIGTERM to stop it and SIGHUP to reload its configuration (`polywan reload` reloads and waits for the result). It behaves the same as under systemd except for the sandbox, which only the unit provides. `polywan run --dry-run` is not a service mode: it computes one plan, logs it and exits.

## Changing the unit

Change the unit with a drop-in (`systemctl edit polywan`), never by editing the installed file, which upgrades replace. Remember `systemctl daemon-reload` after editing a drop-in by hand. Some settings of the configuration need one:

**A configuration file elsewhere** than `/etc/polywan/config.toml`:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/polywan run --config /etc/router/polywan.toml
```

The package's removal runs `polywan cleanup` only with the default path: with another one, stop the daemon and run `polywan cleanup --config PATH` yourself before removing the package.

**A control socket elsewhere** than `/run/polywan/api.sock` (`api.socket`): `systemctl reload` runs `polywan reload`, which uses the default socket, so the reload command needs the path too, and the socket's directory must be writable for the service. A directory below `/run` is best added to the unit's runtime directories, which systemd creates at every start, owned by root with mode 0755, and keeps writable inside the sandbox:

```ini
[Service]
ExecReload=
ExecReload=/usr/bin/polywan reload --socket /run/polywan-ctl/api.sock
RuntimeDirectory=polywan-ctl
```

`RuntimeDirectory=` adds to the unit's list, so `/run/polywan`, which holds the instance lock, stays. After changing the socket in the configuration and in the drop-in, restart the service rather than reloading it: a reload that changes the control socket closes the connection of the command that asked for it, and its outcome is then unknown.

**A status socket elsewhere** (`api.status_socket`) needs its directory added in the same way, and `polywan status --socket PATH` for its clients. A directory outside `/run` needs `ReadWritePaths=` instead, and must exist before the service starts, owned by root and not writable by group or others.

**A state directory elsewhere** (`state_dir`) needs `ReadWritePaths=` for it, created beforehand with mode 0700 and owned by root; the unit's `StateDirectory=` keeps creating `/var/lib/polywan`, which then stays empty. Moving an existing state directory is described in the [configuration reference](configuration.md#state-directory).

The sandbox protects the system from the daemon and from the hooks and mail program it runs (see [email](email.md) for what a mail program can do inside it). Do not weaken it with `NoNewPrivileges=no` or by removing `ProtectSystem=`: such drop-ins are untested and not supported.

## Upgrades and downgrades

An upgrade of the package restarts the daemon only if it was running, and keeps the unit's enablement and masking. With the default `routing.on_shutdown = "keep"`, the routing stays installed across the restart and the new daemon adopts it: established connections continue, and health checks resume after the restart. For the static binary, replace the file and run `systemctl restart polywan`.

Within 2.x, the configuration, the command line, the `/v1` API and the metric names stay compatible. The state files in `/var/lib/polywan` carry a format version: a daemon that finds a manifest or a drain state of a version it does not know refuses to start (exit status 1). A downgrade to a release that does not know the newer format therefore needs `polywan cleanup` with the newer release first; the older release then starts from an empty state. `polywan run --reset-state` discards such files instead, at the cost of the recorded original values of the system settings.

## Stopping

`systemctl stop polywan` with the default `routing.on_shutdown = "keep"` leaves the routing as it is, without health checks: a failed uplink stays in use until the daemon is back. To remove PolyWAN's routing, stop the daemon and run `polywan cleanup`, which removes its rules, routes and nftables table and restores the system settings it changed (where they still have the value it set). With `on_shutdown = "cleanup"`, every stop does the same.

The unit gives the daemon 30 seconds to stop. If a cleanup is interrupted (by that timeout, a crash or a failed kernel operation), the manifest in `/var/lib/polywan` keeps the record of what was installed: run `polywan cleanup` again, as many times as needed; it deletes the manifest only once everything is removed.

## Removing PolyWAN

`apt remove polywan` stops the service and runs `polywan cleanup` with `/etc/polywan/config.toml` before removing the binary. It skips the cleanup, and says so with instructions, when the daemon could not be stopped, when the configuration file is missing, or in a chroot or an alternative root, where the networking may not be the system's; removal continues anyway. If routing was left behind, install PolyWAN again (the package or the static binary) and run `polywan cleanup --config PATH`.

`apt purge polywan` also deletes `/var/lib/polywan`, but only when it holds no manifest, which would mean that PolyWAN's routing may still be installed and that `cleanup` needs it; otherwise it keeps the directory and says why. Purge never deletes `/etc/polywan`, configured paths elsewhere, or the `polywan` group.
