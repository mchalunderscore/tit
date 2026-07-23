# Disaster-recovery exercise

Do this exercise on a disposable copy. Do not damage the active instance.
The commands below use `/srv`. On macOS, use a test directory in
`/usr/local/var`.

1. Stop the disposable service. Copy its configuration and data to a private
   test directory.
2. Start the disposable service with unused listener ports. Make a backup:

   ```text
   tit --config /srv/tit-exercise/config.toml backup /var/backups/tit-exercise.tar
   ```

3. Check the archive:

   ```text
   tit --config /srv/tit-exercise/config.toml doctor --backup /var/backups/tit-exercise.tar
   ```

4. Stop the disposable service. Damage its database. For example, move
   `tit.sqlite3` out of the instance directory.
5. Run `doctor` and confirm that it returns a failure. Do not use a repair
   command for this exercise.
6. Create a different, empty directory with mode 700. Restore the archive:

   ```text
   install -d -m 700 /srv/tit-exercise-restored
   tit restore /var/backups/tit-exercise.tar /srv/tit-exercise-restored
   tit --config /srv/tit-exercise-restored/config.toml doctor
   ```

7. Change the restored configuration to unused listener ports. Start the
   restored service.
8. Confirm that `/healthz` returns status 200. Confirm that a public repository
   page works. Complete an SSH fetch and an administrator login.
9. Stop the restored service. Remove the two disposable directories only after
   you record the exercise result.

Record the release version, backup checksum, damage operation, `doctor` error,
restore duration, and validation result. Repeat the exercise after a storage,
service, or backup procedure change.
