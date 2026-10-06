# Email notifications

PolyWAN sends email about what happens to the uplinks through the system's sendmail interface: it runs a mail program, writes the message to it, and considers the message sent when the program exits successfully. It implements no SMTP, TLS or authentication itself. The one supported and tested configuration is **msmtp**, a small SMTP client that hands the message to a mail server you already use (your provider's, your company's, or a mail service's submission server).

## What you get

With the defaults, a message for each of these events: the daemon started, stopping, reloaded or failed to reload; a path went up or down; an active set changed; an uplink was drained or undrained; the overall status became degraded or recovered. Changes within 30 seconds (`notify.coalesce`) are collected into one message, and at most 20 messages an hour are sent (`notify.email.max_per_hour`), plus one notice when that limit suppresses messages. The subject is `PolyWAN notification`, followed by the router's host name in parentheses when it is a plain DNS name; the body lists the changes in plain text.

`notify.email.events` selects other event types (see [events](api.md#get-v1events)); the list replaces the default. Address and gateway changes, repairs and failed operations are left out by default because they can be frequent. `status_degraded` is sent when the status becomes degraded, not when a further reason is added to an already degraded status.

## Setting up msmtp

The configuration below was tested under PolyWAN's packaged unit, in its complete sandbox, with STARTTLS, server certificate verification and password authentication, on:

| System | systemd | msmtp |
|---|---|---|
| Debian 12 | 252.39 | 1.8.23 |
| Debian 13 | 257.13 | 1.8.28 |
| Ubuntu 26.04 | 259.5 | 1.8.32 |

msmtp's AppArmor profile, which Debian and Ubuntu ship disabled, was also tested in enforce mode. Other mail programs and other configurations of msmtp may accept the same arguments and still fail inside the sandbox; they are not supported.

1. Install msmtp (only the `msmtp` package; `msmtp-mta`, which adds a `/usr/sbin/sendmail` link, is not needed):

   ```sh
   apt install msmtp
   ```

2. Write its system configuration, `/etc/msmtprc`, readable by everyone (it holds no secret):

   ```text
   defaults
   auth on
   tls on
   tls_starttls on
   tls_trust_file /etc/ssl/certs/ca-certificates.crt
   syslog LOG_MAIL

   account polywan
   host smtp.example.com
   port 587
   user router@example.com

   account default : polywan
   ```

3. Put the password in `/etc/netrc`, readable by root only, where msmtp looks for it when the configuration has none:

   ```sh
   install -m 0600 /dev/null /etc/netrc
   echo 'machine smtp.example.com login router@example.com password SECRET' >> /etc/netrc
   ```

4. Configure PolyWAN to use msmtp directly:

   ```toml
   [notify.email]
   from = "router@example.com"
   to = ["admin@example.com", "noc@example.com"]
   sendmail = "/usr/bin/msmtp"
   ```

   `from` and every entry of `to` are plain addresses (`name@domain`), without display names. Your mail server may require `from` to be the account's own address.

5. Reload, then test through the daemon:

   ```sh
   systemctl reload polywan
   polywan notify-test
   ```

   `notify-test` asks the running daemon to send a test message with its accepted configuration, inside its sandbox, and prints msmtp's exit status and error output, for example `TLS certificate verification failed` or `authentication failed`. It is the test that counts: a mail program run from your shell is not confined like the service. msmtp also logs every message to the system log (`syslog LOG_MAIL`).

## How sending works

PolyWAN runs `sendmail -i -f FROM RECIPIENT...` (the configured program, without a shell and without `-t`), writes the complete message to its standard input and closes it. The program runs:

- as root, with no supplementary groups, inside the service's sandbox: the file system is read-only except for PolyWAN's own directories, home directories are hidden, `/tmp` is private, and only IPv4, IPv6, Unix and netlink sockets can be opened;
- with only `PATH=/usr/sbin:/usr/bin:/sbin:/bin` in its environment, `/` as working directory, and no open files other than standard input, output and error;
- in its own process group, with 60 seconds to accept the message.

**Success means accepted by the mail program, not delivered.** Exit status 0 means that msmtp handed the message to the server; later delivery, delays and bounces are the mail system's. A failure (the program cannot be started, exits with another status, is killed, or does not finish within 60 seconds) is retried 1, 5 and 15 minutes later, then the message is dropped and logged. A failure can happen after the server already accepted the message, for example when the connection breaks before the confirmation: the retry then delivers it **twice**. PolyWAN never promises exactly-once delivery.

**Running it as root is a trust decision.** The mail program runs with root's identity, unlike hooks, which run as `notify.hook_user`. PolyWAN checks that the program and every directory above it belong to root and are not writable by others, before every run, and kills the program's whole process group when it times out. These checks do not contain a malicious program, or descendants that leave the process group: configure only a program you trust as root.

**One at a time.** At most one mail program runs at a time, tests and retries included. At most 8 messages wait for sending or a retry; when more arrive, the oldest is discarded and logged. Events that arrive faster than they can be queued are dropped and counted in `polywan_events_dropped_total{notifier="email"}`; failed attempts are counted in `polywan_notifications_failed_total{channel="email"}`.

**Bounded sizes.** A message retains at most 200 changes and 64 KiB of their text, mentioning how many were left out; its body is limited to 128 KiB and the whole message to 512 KiB. The queue of events waiting for a message holds at most 256 events and 1 MiB.

## Reloads, tests and stopping

- A reload that changes `[notify.email]` applies to the messages not yet sent, which are rebuilt with the new settings when needed and keep their identity; a message being sent finishes with the settings it started with. Removing `[notify.email]` discards the pending messages and logs how many. A reload resets neither the hourly limit nor the retry counts.
- `polywan notify-test` bypasses coalescing, the hourly limit and the event selection, and leaves them untouched; it is not retried. It also runs every hook once.
- When the daemon stops, it spends at most 10 seconds sending what is due: the current batch, a message being sent, and messages whose retry is due, once each. Retries not yet due, and whatever remains after 10 seconds, are discarded with a warning. The unit lets a mail program that is running when the stop begins finish its message.
- `polywan notify-test --offline` tests as root from your shell, while the daemon is stopped, outside the sandbox. It says so: a success does not prove that the service can send.

## Other mail systems

Local mail servers (Postfix, Exim, OpenSMTPD) offer a `sendmail` command too, but it usually writes to a queue directory, which the sandbox makes read-only, through setgid helpers, which the sandbox's `NoNewPrivileges=yes` stops from gaining their group. Turning those protections off is not a fix: with the unit's system call filter and without `CAP_SYS_ADMIN`, systemd enforces `NoNewPrivileges` anyway, and a drop-in that weakens the sandbox for the mail program weakens it for the whole daemon. A tested way to queue mail through a local server is planned after 2.0; until then, msmtp submitting directly to a server is the supported configuration.
