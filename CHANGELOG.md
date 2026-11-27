# Changelog

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
- Masq refuses, at startup, a collection that isn't an auth collection.

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
