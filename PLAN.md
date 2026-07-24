# CI/CD plan

This work starts after version 0.1.0. It is not part of the version 0.1.0
release.

## Goal

Add a small first-party runner for repository checks and deployments. Keep the
runner in the `tit` executable. Do not add a second control service.

## Design

- Store the workflow configuration in each repository.
- Use the normal `tit` SSH and repository interfaces to get source and report
  status.
- Run each job in an isolated operating-system process with explicit time,
  memory, disk, and output limits.
- Publish a concise job log and one status for each commit.
- Keep secrets outside repository content and remove them from logs.
- Make interrupted jobs recoverable after a server restart.
- Keep release and artifact signing out of the first runner version.

## Acceptance gate

- A repository owner can add one workflow that runs a command after a push.
- A contributor can see the queued, active, passed, failed, and cancelled
  states.
- A failed or hostile job cannot change another repository or the `tit`
  instance.
- A server restart does not lose the final state of a completed job.
- Linux and macOS tests pass with no external control service.
