# Verified VPS updates

Starting with 0.2.11, the pinned installer embeds its source revision in
connect-control (`build-info`) and exposes it as `core_revision` in the existing
authenticated status API. Success requires the API version and revision to match
the installed binary. On Linux both Core and UI MainPID executable inodes must
match the current release. A responding old server is not sufficient.

An exact repeat checks the running release without rebuilding. If unhealthy,
it restarts only CONNECT Core/UI, then checks again. Foreign service files are
still refused; custom systemd overrides are not overwritten. A manifest/current
release mismatch is reported explicitly. Existing credentials, devices and
revocations remain in place. Fresh compilation uses one package at a time,
GOMAXPROCS=2 and a Go runtime soft memory target of 512 MiB; this is not a hard
host-wide memory limit or a change to neighboring services.

Regression validation includes a running executable with a stale inode in the
disposable systemd installer test, successful repeat recovery, failed-update
rollback, login and preserved revocation, plus unit rejection of old versions,
wrong revisions and wrong executable inodes. This does not establish why a
particular existing VPS stayed on 0.2.6 without its actual installer output.

Before SSH-updating the same server, disconnect CONNECT so restarting it does
not interrupt the SSH transport inside the VPN. Other VPNs need not be stopped.
The final output must include `Verified running Core` (or `already installed AND
running`) and the requested revision. If it fails, retain the final error instead
of repeating the command or uninstalling the existing installation.
