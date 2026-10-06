# Security policy

## Supported versions

Security fixes are released for the latest 2.x release. Fault Tolerant Router 1.x, the Ruby daemon on the `legacy/ruby` branch, is no longer maintained.

## Reporting a vulnerability

PolyWAN runs as root on routers, so please report vulnerabilities privately: open the repository's **Security** tab and choose **Report a vulnerability**, or write to alessandro@zarrilli.net. Do not open a public issue.

Please include the version (`polywan --version`), how PolyWAN was installed, and the steps or configuration that show the problem. The advisory is published together with the release that fixes the problem.

Behaviour that the documentation describes as intended is not a vulnerability, for example that the status socket is readable by every local user unless `api.status_group` restricts it, that members of `api.group` control the daemon, or that the metrics endpoint has no access control (see [who can do what](docs/api.md#who-can-do-what)).
