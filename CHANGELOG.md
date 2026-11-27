# Changelog

## Unreleased

### Security

- Return (the stop endpoint) removes the borrowed session in a transaction, the same way the per-request
  check does, with one shared piece of code. Before, stop read the target's sessions and wrote them back with
  no transaction, so a sign-in the target made in between was lost, and two stops at once both reported
  `onStop`. Now a sign-in made meanwhile is kept, and stops that arrive together report `onStop` once.
- Stop fails closed. If the delete can't be confirmed after three tries, the response is a 500 with
  `ok: false`, every masquerade cookie is cleared, the masquerader's own token is not handed back, the browser
  goes to the login page, `onStop` is not called, and the failure is logged as an error with the masquerader
  and target ids. The borrowed session may then still be alive until its hour runs out; the per-request check
  still covers it. Before, the error left the borrowed token in the browser.
- `onStop`'s `expired` is true only when the borrowed session had really ended before the stop. Before, any
  stop where the state cookie and the signed-in token didn't match, or where the browser had lost the
  borrowed token, reported `expired: true` while the session was still alive, and left it alive.
- The state cookie now carries the borrowed session's id, and stop ends exactly that session: also when the
  browser lost the borrowed token, and when another token signs in beside the cookie. That other session is
  never ended or reported. A state cookie issued by 0.1.2 or earlier has no session id and lasts up to 24
  hours: with it, stop ends the signed-in borrowed session only when masquerader and target match, as in
  0.1.2, and otherwise ends nothing and reports `expired: true` only once the hour is over.

### Known limits

- A second stop that arrives after the first has finished finds the session gone and reports `onStop` again
  with `expired: true`. Only stops that overlap are reported once.

Tested with Vitest against an in-memory MongoDB replica set, through Payload's REST router: 17 new tests in
`test/stop.test.ts` (11 failed on 0.1.2) and three older tests updated, 107 in all. Not tested: Postgres or
SQLite, a database without transactions, a real browser, and a real database outage (the failed delete is
simulated by making the write throw).

## 0.1.2 (2026-11-26)

### Security

- A borrowed session is checked on every request. Before, a masquerade kept working for the
  rest of its hour after the masquerader lost the right to it, and a borrowed token sent as
  `Authorization: Bearer` with no cookie kept it working with nothing to say it should stop.
  Now each request that carries a borrowed token asks `canMasquerade` again, with both users
  loaded fresh. A no deletes the borrowed session, so that request and every later one run
  signed out. If the check can't finish, because a read or the delete fails, the borrowed
  token is ignored for that request, so it still runs signed out.
- The per-request check's delete reads the target's sessions again in a transaction, so a sign-in
  the target makes while a check is running is kept, and several requests at once report `onStop`
  once. This covered the check only. Stop still deleted without a transaction in 0.1.2; see
  Unreleased.
- Masq refuses a collection that isn't an auth collection, a `useSessions` other than `true` or
  left out (with sessions off there is no session to delete, so the recheck could never end a
  borrowed token), and a `readOnly` that isn't `true` or `false` (before, `0` turned read-only
  off). The sessions check runs when the config is built and again when Payload starts, so a
  plugin listed after Masq can't turn sessions off unnoticed. If sessions are off anyway, a
  borrowed token signs nobody in and start refuses.
- A borrowed token repeated in the cookie, or sent in the cookie and the header, is checked once.
- Stop ends the borrowed session the request is signed in with, matched by user and session, and
  with the state cookie only when it names that same masquerader and target.
  Before, with one borrowed token in the header and another in the cookie, it could end the wrong
  one or neither, report the wrong masquerader to `onStop`, or, when the target's own token signed
  in, delete the target's own session.
- A borrowed token is recognized however Payload would accept it. Before, padding or a space in
  the signature, or a space around the cookie name, signed in as the target while Masq didn't see
  the token as borrowed, so the recheck, read-only mode and the refresh refusal all missed it.

### Added

- `recheck` option: an extra per-request check after `canMasquerade`. Only exactly `true`
  passes.
- `onStop` gets `revoked: true` when the per-request check ended the session.

## 0.1.1 (2026-11-11)

### Upgrading

- **Required:** before or right after upgrading, end every running masquerade. The documented
  commands clear everyone's sessions, which signs every user out once. See "Upgrading from
  0.1.0" in the README.

### Fixed

- Read-only now refuses every write Payload 3.92 runs hooks for: restoring collection and global
  versions, unlock, forgot-password and reset-password, as well as create, update and delete.
  Global restores, which skip `beforeChange`, are refused in `beforeOperation`.
- The borrowed token carries a `masqBy` claim, so read-only, no-nesting and the components hold
  when the masquerade cookie is cleared, and the borrowed session can't be refreshed past its hour.
- Return ends the borrowed session even when the masquerade cookie is gone. The `masqBy` claim
  counts only on a token signed with Payload's secret, and only for the user the request is
  signed in as, so a forged or misplaced claim can't end a session or record an `onStop`.
- The banner names the target only while the borrowed session is live and still allowed.
- `canMasquerade` must answer exactly `true`; a truthy value or a thrown error is a no (403, or
  nothing rendered), never a 500.
- The list cell, nav link and Masquerade view hide while masquerading, like the account-page button.

## 0.1.0

- First release.
