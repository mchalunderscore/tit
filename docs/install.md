# Install and remove tit

This procedure installs one `tit` instance. The default instance directory is
`/srv/tit`. The release package contains the executable, configuration
example, service examples, Caddy example, manual, shell completions, upgrade
procedure, and disaster-recovery exercise.

## Verify the release package

Download one archive and its adjacent `.sha256` file from the same release.
Use the archive for your operating system and architecture. Then, compare its
SHA-256 checksum:

```text
sha256sum -c tit-VERSION-TARGET.tar.gz.sha256
```

On macOS, use this command:

```text
shasum -a 256 -c tit-VERSION-TARGET.tar.gz.sha256
```

The checksum detects a damaged download. Confirm that you got the checksum
from the expected release before you use the archive.

## Install the files

Extract the archive. Select the instance directory and service account. Use
`/srv/tit` and `tit` on Linux, FreeBSD, and NetBSD. Use `/srv/tit` and `_tit`
on OpenBSD. Use `/usr/local/var/tit` and `_tit` on macOS because `/usr/local`
is on the writable macOS data volume.

Run these commands as `root` after you set `instance` and `account`:

```text
instance=/srv/tit
account=tit
install -m 755 tit-VERSION-TARGET/bin/tit /usr/local/bin/tit
install -d -m 700 "$instance"
chown "$account" "$instance"
install -m 600 tit-VERSION-TARGET/etc/tit/config.toml "$instance/config.toml"
chown "$account" "$instance/config.toml"
```

Create a dedicated system account before these commands. Give the account no
login shell and no password. Use `tit` on Linux, FreeBSD, and NetBSD. Use
`_tit` on macOS and OpenBSD. The supplied service examples use these names.
Use the native account administration command for the operating system. Do not
give the account an interactive login or an administrator role.

Edit the installed `config.toml`. Set `public_url`, the listener addresses, and
the public SSH hostname and port. Keep the file and directory readable only by
the service account.

Install the applicable files from `share`:

- Linux: install `share/doc/tit/examples/tit.service` in
  `/etc/systemd/system/tit.service`.
- macOS: install `share/doc/tit/examples/com.tit-cde.tit.plist` in
  `/Library/LaunchDaemons/com.tit-cde.tit.plist`.
- FreeBSD: install `share/doc/tit/examples/tit.freebsd` in
  `/usr/local/etc/rc.d/tit`.
- OpenBSD: install `share/doc/tit/examples/tit.openbsd` in `/etc/rc.d/tit`.
- NetBSD: install `share/doc/tit/examples/tit.netbsd` in `/etc/rc.d/tit`.
- Caddy: copy the supplied `Caddyfile` content into the site configuration and
  change `tit.example` to the public hostname.

The package also supplies a `tit.1` manual and completions for Bash, Zsh, and
Fish. Copy them to the matching system directories if the package manager does
not do this operation.

## Configure the first administrator

The commands below use `/srv/tit`. On macOS, use `/usr/local/var/tit`.

Run the setup command as the service account:

```text
tit --config /srv/tit/config.toml setup admin USERNAME "SSH_PUBLIC_KEY"
```

Store the printed recovery credential offline. The command prints it one time.
Then, run the read-only check:

```text
tit --config /srv/tit/config.toml doctor
```

The first `doctor` check requires the SSH host key. Start and stop the service
one time if the file does not exist. Then, run `doctor` again.

## Start the service

Use the native service manager:

```text
systemctl enable --now tit
```

On macOS, use `launchctl bootstrap system
/Library/LaunchDaemons/com.tit-cde.tit.plist`. On a BSD system, enable `tit`
in the applicable system configuration:

- FreeBSD: run `sysrc tit_enable=YES` and `service tit start`.
- OpenBSD: run `rcctl enable tit` and `rcctl start tit`.
- NetBSD: add `tit=YES` to `/etc/rc.conf` and run `service tit start`.

Request `/healthz` through Caddy. Status 200 shows that the HTTP and SSH
listeners are ready.

## Remove the service

Make a final backup before removal. Stop and disable the native service:

- Linux: run `systemctl disable --now tit`.
- macOS: run `launchctl bootout system/com.tit-cde.tit`.
- FreeBSD: run `service tit stop` and `sysrc tit_enable=NO`.
- OpenBSD: run `rcctl stop tit` and `rcctl disable tit`.
- NetBSD: run `service tit stop` and remove `tit=YES` from `/etc/rc.conf`.

Remove the service file, `/usr/local/bin/tit`, the manual, and the shell
completions. Reload the service manager when it requires this operation.

Keep `/srv/tit` if you can need its repositories, credentials, or audit
history. To remove all instance data, remove `/srv/tit` only after you verify
the final backup and its storage location. This operation cannot be reversed
without a backup.
