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

## 0.2.12: prebuilt server packages

Normal VPS installation downloads a Linux amd64/arm64 server package published
for the exact requested source SHA. GitHub release metadata must name that SHA
and provide a SHA256 digest. The installer verifies the archive digest, strict
file list, architecture, per-file checksums, and executable build identity before
stopping services. No Go toolchain, module cache or source compilation is needed
on the VPS. Missing/corrupt packages fail explicitly instead of silently falling
back to a large source build. Free space is checked before extraction and release
copying; existing data and unrelated files are not removed to free space.

Explicit developer `--source` builds remain available. Their work/cache/module
directories are confined to a private /var/tmp stage, including GOTMPDIR, rather
than filling a small /tmp filesystem. --package with --package-sha256 supports
verified offline installation and the disposable systemd integration test.

The reported 0.2.11 failure is a confirmed compiler write failure in /tmp with
ENOSPC. It happened before release switching. The output alone does not identify
whether the limiting resource was a separate /tmp mount, the root filesystem,
or filesystem inode capacity. No production cleanup was performed by the agent.
