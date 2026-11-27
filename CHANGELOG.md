# Changelog

## Unreleased

### Upgrading

- **Masq now needs a database that runs transactions, and checks at start-up.** It begins a transaction, reads
  in it and commits. If that fails, Payload doesn't start, and the error says why. A standalone MongoDB (no
  replica set) fails this check, and so does an adapter with transactions turned off. To run without
  transactions anyway, set `allowNoTransactions: true`. That is unsafe when requests overlap: see the README.
  On a standalone MongoDB also set `transactionOptions: false` on the adapter, as Payload itself needs there.

### Fixed: the order of starts and stops that arrive together

- Return (the stop endpoint) removes the borrowed session in a transaction, the same way the per-request
  check does, with one shared piece of code. Before, stop read the target's sessions and wrote them back with
  no transaction, so a sign-in the target made in between was lost, and two stops at once both reported
  `onStop`. Now a sign-in made meanwhile is kept. In tests, four and eight stops of one session that had all
  signed in before any of them removed it report `onStop` once.
- Start adds the borrowed session the same way: the target's sessions are read again inside a transaction right
  before the write. Before, start wrote back the sessions it had read before asking `canMasquerade`, so a
  return or a sign-in that happened while it was deciding was undone. If the target was deleted meanwhile,
  start answers 404. If the session can't be added, start answers 500, hands out no token and logs an error.
- Starts, stops and per-request checks that change one user's sessions at once now wait a short random time
  before trying again, up to twelve tries (the waits add up to about two seconds at most). Before, there were
  three tries with no wait, and four or more at once could give up with the session still alive. Tested with
  eight masquerades of one user stopped at once, and four started at once.
- Masq no longer changes sessions without a transaction. Before, it quietly fell back to a plain read and
  write when the adapter gave none. Now start-up refuses (see Upgrading). If the start-up check was skipped,
  start refuses with a 500, stop fails closed as below, and the per-request check runs the request signed out.
- Stop fails closed. If the delete can't be confirmed after twelve tries, the response is a 500 with
  `ok: false`, every masquerade cookie is cleared, the masquerader's own token is not handed back, the browser
  goes to the login page, `onStop` is not called, and the failure is logged as an error with the masquerader
  and target ids. The borrowed session may then still be alive until its hour runs out; the per-request check
  still covers it. Before, the error left the borrowed token in the browser. A failure to begin the
  transaction is now tried again like any other step.
- An `onStop` that throws on Return no longer turns the answer into a 500 with the cookies left in the browser.
  The session is already ended by then, so the error is logged and the browser gets its normal answer.
- If a commit throws and the session then turns out to be gone, nobody can tell which request removed it, and
  `onStop` may go unreported for that stop. That is now logged as an error with the target's id.
- `onStop`'s `expired` is true only when the borrowed session had really ended before the stop. Before, any
  stop where the state cookie and the signed-in token didn't match, or where the browser had lost the
  borrowed token, reported `expired: true` while the session was still alive, and left it alive.
- The state cookie now carries the borrowed session's id, and stop ends exactly that session: also when the
  browser lost the borrowed token, and when another token signs in beside the cookie. That other session is
  never ended or reported. A state cookie issued by 0.1.2 or earlier has no session id and lasts up to 24
  hours: with it, stop ends the signed-in borrowed session only when masquerader and target match, as in
  0.1.2, and otherwise ends nothing and reports `expired: true` only once the hour is over.
- In 0.1.2 only the per-request check deleted in a transaction. Stop and start did not until this release.

### Added

- `allowNoTransactions` option, default `false`.

### Known limits

- Payload's own sign-in is outside Masq's reach. It reads the user, checks the password and then writes the
  user back with the sessions it read first. A sign-in by the target that lands at the same moment as a
  start or a return of a masquerade of them can therefore put an ended borrowed session back, or drop one that
  just started. A session that comes back this way is still marked as borrowed: read-only, checked on every
  request, not refreshable, and over with its hour.
- More than eight changes to one user's sessions at the same moment are not tested. Past twelve tries a start
  or stop gives up and answers 500, as above.
- A second stop that arrives after the first has finished finds the session gone and reports `onStop` again
  with `expired: true`. Only stops that overlap are reported once.

Tested with Vitest against an in-memory MongoDB, through Payload's REST router: a replica set for
`test/stop.test.ts` (27 tests) and a standalone server with no transactions for `test/transactions.test.ts`
(6 tests), 123 in all. Not tested: Postgres or SQLite (the start-up check included), a real browser, a
real database outage or lost connection (failures are simulated by making one adapter call throw), and the
overlap with Payload's own sign-in described under Known limits.

## 0.1.2 (2026-11-26)

### Security

- A borrowed session is checked on every request. Before, a masquerade kept working for the
  rest of its hour after the masquerader lost the right to it, and a borrowed token sent as
  `Authorization: Bearer` with no cookie kept it working with nothing to say it should stop.
  Now each request that carries a borrowed token asks `canMasquerade` again, with both users
  loaded fresh. A no deletes the borrowed session, so that request and every later one run
  signed out. If the check can't finish, because a read or the delete fails, the borrowed
  token is ignored for that request, so it still runs signed out.
- The delete reads the target's sessions again in a transaction, so a sign-in the target makes
  while a check is running is kept, and several requests at once report `onStop` once.
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
