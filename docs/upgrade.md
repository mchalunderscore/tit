# Upgrade tit

Use this procedure for an upgrade to a new release. Do not replace a running
executable before you make a backup.

The commands below use `/srv/tit`. On macOS, use `/usr/local/var/tit`.

1. Read the release notes and the new `config.example.toml`.
2. Download the archive and its `.sha256` file. Verify the checksum as
   specified in `install.md`.
3. Make an online backup:

   ```text
   tit --config /srv/tit/config.toml backup /var/backups/tit-before-upgrade.tar
   ```

4. Check the active instance and the backup:

   ```text
   tit --config /srv/tit/config.toml doctor --backup /var/backups/tit-before-upgrade.tar
   ```

5. Stop the native service. Keep a copy of the old executable outside
   `/srv/tit`.
6. Install the new `bin/tit` with mode 755. Do not replace the configuration
   with the example.
7. Run the new read-only check:

   ```text
   /usr/local/bin/tit --config /srv/tit/config.toml doctor
   ```

8. Start the service. Request `/healthz` and complete one HTTP login and one
   SSH fetch.

If the new executable does not accept the current configuration or data, stop
it. Restore the old executable. If the new release changed the instance before
it failed, restore the backup to a new, empty directory. Do not restore into
the damaged directory. Activate the restored directory only after `doctor`
passes.
