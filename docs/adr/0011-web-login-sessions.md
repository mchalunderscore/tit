# Architectural decision record 0011: Web login sessions

Status: Accepted

Date: 2026-07-22

## Context

The Web UI must use the same SSH key identity as the SSH server. A login
challenge must not be reusable. A database copy must not contain a session
token or a CSRF token that a user can use directly.

## Decision

The login form requires a username and an active SSH public key. The server
creates a five-minute `tit-auth-v1` challenge and stores only the SHA-256 hash
of its random nonce. The user signs the exact challenge with the `tit-auth`
SSHSIG namespace and pastes the complete SSHSIG envelope into the Web UI.

The server verifies the origin, username, key fingerprint, time, namespace,
signature algorithm, and signature. The user can paste the envelope or upload
the signature file. An HTML form changes challenge line endings to CRLF. The
HTTP interface changes these line endings back to LF before signature
verification. In one SQLite transaction, the server consumes the nonce and
creates a seven-day session. The response stores an opaque session
token in an `HttpOnly` cookie and a CSRF token in a second cookie. Both cookies
use `SameSite=Strict`. HTTPS responses also use `Secure`. SQLite stores only
SHA-256 hashes of both values.

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

The server keeps a maximum of 1,024 active login nonces and removes consumed or
expired nonces before it creates one. Cookie parsing rejects duplicate, empty,
and oversized values. A session is not
valid after its expiry, account suspension, logout, or a privilege change. A
CSRF failure does not end the session because an external request must not be
able to log out a user.

## Evidence

The session test signs with stock `ssh-keygen`, restarts the login service
between issue and verification, rejects challenge replay and a bad CSRF token,
checks the stored hashes, invalidates a session after key addition, and tests
the function that ends all sessions. The executable test completes login and
logout through HTTP with browser CRLF line endings. It rejects an incorrect
upload content type and malformed multipart content. It also confirms CSRF
rejection and session invalidation.

## Consequences

The user must supply the public key during login so the server can select the
correct key without an account-enumeration page. The interface accepts a pasted
SSHSIG envelope or an SSHSIG file.
