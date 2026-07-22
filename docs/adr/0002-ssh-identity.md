# Architectural decision record 0002: SSH identity

Status: Provisional

Date: 2026-07-22

## Context

`tit` needs one SSH identity for Git transport, SSH commands, and Web login.
The SSH username must not select the account. The SSH public key must select
the account. Web login must use the standard SSHSIG format and must prevent
replay.

## Decision

Use `ssh-key` version 0.7.0-rc.11 for OpenSSH public-key parsing,
fingerprints, and SSHSIG verification. Russh version 0.62.4 uses this exact
version, which prevents two SSH key models in the executable. Use Russh with
the `ring` feature for the built-in SSH server. Do not enable compression or
the Russh RSA feature. Use Tokio for the asynchronous listener. Use `rand` for
operating-system random bytes and `sha2` for login nonce hashes.

Accept Ed25519 and ECDSA P-256 public keys. Remove the public-key comment during
normalization and use its SHA-256 fingerprint. Reject DSA, other ECDSA curves,
security keys, certificates, unknown algorithms, and RSA. Report an RSA key
that is smaller than 3,072 bits as undersized before the general RSA rejection.

Russh advertises RSA-SHA2, but its server handler does not receive the RSA
signature algorithm that the client selected. Thus, the application cannot
independently reject a custom client that uses RSA-SHA1. Do not accept RSA keys
until this boundary can enforce RSA-SHA2. A stock OpenSSH client that is forced
to use `ssh-rsa` cannot authenticate to the M1B server.

Use this canonical login challenge:

```text
tit-auth-v1
purpose=web-login
origin=ORIGIN
username=USERNAME
fingerprint=FINGERPRINT
nonce=NONCE
issued-at=ISSUED_TIME
expires-at=EXPIRY_TIME
```

The trailing newline is necessary. Sign the exact bytes with the `tit-auth`
SSHSIG namespace. A challenge is valid for a maximum of five minutes. The
challenge is at most 4 KiB. The SSHSIG envelope and SSH public key are each at
most 16 KiB.

Keep only the SHA-256 hash and expiry of each active login nonce. Keep a maximum
of 1,024 active challenges and remove expired entries when a new challenge is
issued. Consume the hash under one lock only after all context and signature
checks pass. A process restart invalidates all challenges in this feasibility
implementation. Milestone 3 must put nonce hashes in SQLite before Web login is
available.

The SSH server accepts public-key authentication only. It ignores the SSH
username. It accepts session channels and the exact `tit --version` command.
It rejects shells, PTYs, subsystems, agents, forwarding, and all other exec
requests. It accepts only `GIT_PROTOCOL` environment requests with the exact
values `version=0`, `version=1`, or `version=2`.

## Threats and controls

A copied SSHSIG envelope cannot start a second session because the first valid
verification removes its nonce hash. Concurrent verification can have only one
successful result. A signer cannot change the origin, username, fingerprint,
issue time, or expiry because these fields are in the signed bytes. The verifier
also compares these fields with its own origin, username, selected key, clock,
and stored expiry.

The key and signature parsers have input limits before cryptographic work. The
server has only public-key authentication, three authentication attempts, a
30-second inactivity limit, and a 32-KiB packet limit from Russh. Rejected SSH
requests do not start a shell or a process.

## Evidence

The local macOS gate uses stock `ssh`, `ssh-agent`, `ssh-add`, and `ssh-keygen`.
It verifies Ed25519 and ECDSA P-256 authentication with two different SSH
usernames. It verifies SSHSIG envelopes that stock `ssh-keygen -Y sign` creates.
It also verifies the negative cases for replay, concurrent use, expiry, origin,
namespace, key, malformed input, DSA, ECDSA P-384, RSA, RSA-SHA1, an unknown
key, shells, PTYs, subsystems, agents, forwarding, arbitrary exec requests, and
environment values.

This decision stays provisional until the Linux and macOS hosted M1B gates
pass.

## Consequences

The selected crates add cryptographic and asynchronous code to the executable,
but they remove custom SSH cryptography and transport code. The initial key set
is smaller because Russh does not give the application the information that it
needs to enforce RSA-SHA2. This omission is safer than acceptance of RSA-SHA1.

The server boundary is not connected to `tit serve` in M1B because the account
store and instance host-key lifecycle do not exist. The server accepts an
explicit set of normalized keys. Subsequent milestones must supply that set
through the account and authorization services without changing the transport
policy.
