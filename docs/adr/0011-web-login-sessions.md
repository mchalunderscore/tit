# Architectural decision record 0011: Web login sessions

Status: Accepted

Date: 2026-07-22

Amended: 2026-07-24

## Context

The Web UI must use the same SSH key identity as the SSH server. A login
challenge must not be reusable. A database copy must not contain a session
token or a CSRF token that a user can use directly.

## Decision

The primary login form creates a five-minute SSH approval. The Web UI shows an
exact `ssh` command with a random one-time secret. The browser stores a
different login CSRF value in an `HttpOnly` cookie. SQLite stores only the
SHA-256 hashes of these two values.

The user runs the command against the built-in SSH server. Public-key
authentication selects the account and active key. The `login` command binds
the pending approval to that account and key in one transaction. Its output
shows the Web origin and account. The browser supplies the one-time secret and
the matching login CSRF value when it completes the login. In one SQLite
transaction, the server consumes the approval and creates a seven-day session.

The fallback form requires only a username. The server creates a five-minute
`tit-auth-v2` challenge and stores only the SHA-256 hash of its random nonce.
The user downloads and signs the exact challenge with the `tit-auth` SSHSIG
namespace. The SSHSIG envelope contains the signing public key. The server
verifies that this key is active on the named account. The user can upload the
signature file or paste the complete envelope. An HTML form changes challenge
line endings to CRLF. The HTTP interface changes these line endings back to LF
before signature verification. A failed signature returns the same challenge
page so that the user can try again before it expires.

The response stores an opaque session token in an `HttpOnly` cookie and a CSRF
token in a second cookie. Both cookies use `SameSite=Strict`. HTTPS responses
also use `Secure`. SQLite stores only SHA-256 hashes of both values.

Challenge creation also sets a five-minute, `HttpOnly` login CSRF cookie. The
verification form must submit the matching value, and the nonce row stores only
its hash. Thus, a different site cannot complete a login in the user's browser.

Each state-changing account form must compare its submitted CSRF token with the
CSRF cookie and the stored hash. The initial account page supplies a logout
form that uses this rule. Logout ends all sessions for the account. Recovery,
key addition, key revocation, suspension, and restoration also end all account
sessions in the same transaction as the privilege change.

## Failure and threat cases

Login and signature forms have fixed body limits. Axum limits the request body,
and `multra` parses the uploaded form as a stream within the 64-KiB limit.
Challenge and SSHSIG parsing have the
authentication limits from architectural decision record 0002. A bad
identity, signature, expired challenge, and consumed challenge use a common Web
UI error. The response does not disclose which input failed.

The server keeps a maximum of 1,024 active login nonces and 1,024 active SSH
approvals. It removes consumed or expired records before it creates one.
Cookie parsing rejects duplicate, empty, and oversized values. A session is
not valid after its expiry, account suspension, logout, or a privilege change.
A CSRF failure does not end the session because an external request must not
be able to log out a user.

## Evidence

The session test signs with stock `ssh-keygen`, restarts the login service
between issue and verification, rejects challenge replay and a bad CSRF token,
checks the stored hashes, invalidates a session after key addition, and tests
the function that ends all sessions. It also verifies approval binding and
concurrent one-time consumption.

The executable test creates an approval through HTTP, approves it with stock
`ssh`, and completes the browser session. It also completes the fallback with
stock `ssh-keygen` and browser CRLF line endings. It rejects an incorrect
upload content type and malformed multipart content. It confirms CSRF
rejection and session invalidation.

## Consequences

The primary flow needs access to the built-in SSH service. The fallback works
when the user cannot connect to that service. Neither flow asks the user to
copy a public key.
