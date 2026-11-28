# Changelog

## 0.1.3 (2026-11-28)

### Security

- Start (`POST /:id/masq`) no longer tells someone who isn't allowed whether a user exists.
  Someone `canMasquerade` refuses with no target now gets the same 403 for every other id it
  won't let them use, whether a user has it or not.
- Start now goes by the id of the account it finds, however the request spelled it. The check
  that you aren't choosing yourself, the masquerade's record and everything after it, including
  `onStop`'s `targetId`, the banner and the return, use that one id. This covers text ids and
  number ids.
- A masquerade started before this upgrade may have recorded the target's id as the request
  spelled it. Stop now looks that account up when the spellings differ. If its own id is the
  borrowed session's, stop deletes the session, and `onStop` (with `expired: false`) and the
  return use that id. If the lookup fails or finds anything else, stop answers as it did before.

Answers a client might rely on that change:

- For someone who may not use masquerade at all, an id no user has, or one that isn't a valid
  id, answers 403 "You may not masquerade as this user." (404 "User not found." for a missing
  user before).
- For someone who may use masquerade, a user they're refused and their own read access doesn't
  find answers 404 "User not found." (403 before). A refused user they can read still answers
  403. If your `canMasquerade` doesn't answer `true` with no target, they get 403 for missing
  users too.
- If loading the user fails (a database error or a read hook that throws), start logs it and
  gives the same answer as for a missing user (an error response before).
- Your own account, in any spelling of its id the database accepts, answers 400 "Choose another
  user.", and `canMasquerade` isn't asked about it.
- A looked-up user that comes back with no usable id (not a non-empty string or a finite
  number, for example after a read hook changes it) counts as not found.

Who can masquerade as another user is unchanged.

Stop after an upgrade was tested through Payload's REST router with its usual text ids, using
a state cookie signed again in the test with another spelling. Lookup failures and unusable
results were mocked. Not tested for it: number ids, a real upgrade of a running app, Postgres
or SQLite, or a browser. The banner is unchanged and wasn't tested with an older spelling. A
reviewer ran the new tests against the old source: 11 of the 13 fail there.

Tested through Payload's REST router with MongoDB in memory, with its usual ids and with a
number `id` field. Refusals were compared by status, body and headers, those for someone who
may not use masquerade with Payload's `debug` off and on too. The banner was rendered in the
test harness. Not tested: Postgres or SQLite, GraphQL for these changes, a real Next.js server
or browser, and response timing, which this change doesn't try to even out.

### Development

- The Payload dev dependencies used by the tests move to 3.94.2, which brings mongoose 8.24.7
  and clears `npm audit`. Peer ranges are unchanged, and mongoose isn't in the published
  package. Tested with the full suite (134 tests) and the typecheck; not tested in a host app.

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
