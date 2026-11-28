# payload-plugin-masq

Masquerade for [Payload](https://payloadcms.com) 3: an admin signs in as another user to see
the site and admin exactly as they do, then returns to their own account with one click.
Built for support and troubleshooting.

> **Beta (0.x).** Used in production on a live site. Feedback and issues welcome.

## What you get

- **Masquerade as this user**: a button on each account page, shown only to people allowed
  to masquerade as that user.
- **Masquerade area** (`/admin/masquerade`): a "Masquerade as…" autocomplete for quick
  switching, plus a user search with a Masquerade button on every result. Only people allowed to
  masquerade see it, and the search reads with their own access, so it never lists anyone
  they could not already see. The users list gets a Masquerade column with a button per row.
- **A banner** in the admin (and on your site, with `<MasqueradeBanner />`): who you are
  masquerading as, the time left, and **Return to my account**. Once the borrowed session is
  over, or you're no longer allowed to masquerade as that user, it names nobody and only offers
  the way back.
- **A real, short session**: the masquerader gets a genuine Payload session of the target
  (the same mechanism as a normal login, sessions included), so every access rule applies
  exactly as for that user. One hour by default, and it can't be refreshed past that.
- **Safe return**: your own token waits in an httpOnly cookie sent only to the stop endpoint,
  and comes back only if it is still valid and you are still allowed to masquerade. The
  borrowed session is ended when you return.
- **Audit hooks**: `onStart` (with an optional reason) and `onStop`, and `masqueraderOf(req)`
  so your audit trail can record who really made a change.
- **Read-only** (default): look everywhere the user can, but change nothing. While
  masquerading, Payload refuses (403) on every collection: create, update, delete (single and
  bulk), restoring a version, unlock, forgot-password and reset-password; and on every global:
  update and restoring a version. That holds over REST, GraphQL and the Local API when you pass
  the request. The borrowed token itself is marked, so clearing the masquerade cookie doesn't
  lift it, whether the token comes in the cookie or an `Authorization` header. Still allowed:
  reads, Payload's own bookkeeping (preferences, document locks), signing in, signing out, and
  the plugin's own return. Not covered: your own endpoints and server actions (call
  `assertNotMasquerading(payload, headers)` there), Local API calls made without the request,
  and email verification links, which Payload runs without hooks. If your site lets signed-in
  users call `/api/payload-jobs/run`, a masquerader can start jobs that are already queued;
  Masq doesn't block that.
- **A leftover masquerade cookie** lasts up to 24 hours if you never press **Return to my
  account** (for example, the borrowed hour ran out). Until it's cleared, that browser is
  treated as masquerading, so forgot-password and other writes answer 403. Press **Return to my
  account** in the banner to clear it, or wait for the cookie to expire.
- **`canMasquerade` must answer exactly `true`.** A truthy value, or an error it throws, is a
  no: the endpoints refuse and the components show nothing.
- **Refusals don't say who exists.** If `canMasquerade` with no target isn't `true` for you,
  start answers the same 403 for every other id it won't let you use, whether or not a user has
  it. If it is `true`, you get 404 "User not found." for a missing user, and the same 404 for a
  refused user your own read access doesn't find; a refused user you can read answers 403. So
  make `canMasquerade` answer `true` with no target for the people who may use masquerade.
  A failure while loading the user is logged and answered like a missing user. Response times
  aren't evened out.
- **Checked on every request.** While a borrowed session is live, every request that carries
  its token, in the cookie or an `Authorization` header, asks `canMasquerade` again with the
  masquerader and the target loaded fresh, then your `recheck` if you set one. If the answer
  is no (the masquerader was demoted or deleted, or the target changed so the rule refuses),
  the borrowed session is deleted on that request, the request runs signed out, and `onStop`
  gets `revoked: true`. If the check itself fails (a read or the delete throws), the borrowed
  token is ignored for that request, so it runs signed out. The cost is two reads by ID on
  requests that carry a borrowed token, and nothing on any other request.
- **Limits of the check.** It is an auth strategy that Masq puts first on its collection, so an
  auth collection listed before it, or a strategy another plugin puts in front later, runs
  before it. Signing the masquerader out everywhere doesn't end a borrowed session; if that
  should end it, check it in `recheck`. `recheck` runs before anyone is signed in, so
  `req.user` isn't set yet; use the `masquerader` and `target` it gets. The token is read from
  the cookie even on cross-site requests, the same as Payload's own sign-in. Behind a Next.js
  `basePath`, stopping a revoked masquerade can report `onStop` twice.
- Never as yourself, no nesting, no public endpoints: masquerading needs a signed-in user the
  rules allow.

## Upgrading from 0.1.0

Required, once: before or right after upgrading, end every running masquerade. Borrowed
sessions started by 0.1.0 carry no mark, so with the masquerade cookie cleared they can still
write, and Payload keeps refreshing them. There is no sound way to tell them apart from normal
sessions afterwards. A borrowed session is stored on the **target's** account, so signing the
masquerader out isn't enough. The commands below clear **everyone's** sessions, so every user
is signed out once and signs in again. (Clearing only the masqueraded users' sessions would be
enough, but no command for that is given here because none has been tested.)

With the Local API (any database adapter; tested), for the default `users` collection:

```ts
await payload.db.updateMany({ collection: 'users', where: {}, data: { sessions: [] } })
```

Or on MongoDB from the command line (the same change, not tested here):

```sh
mongosh "$DATABASE_URI" --eval 'db.users.updateMany({}, { $set: { sessions: [] } })'
```

From 0.1.2, Masq needs `useSessions` left out or set to `true` on its auth collection, because it
ends a borrowed token by deleting its session. Any other value (`false`, `0`, an empty string)
stops the build. It checks again when Payload starts, so a plugin listed after Masq or a change
to the built config that turns sessions off stops start-up too. If sessions are off anyway, for
example when start-up checks were skipped, no borrowed token signs anyone in and no masquerade
can start. If you ran 0.1.0 or 0.1.1 that way, changing
`PAYLOAD_SECRET` is the only way to end the old tokens, and it signs everyone out.

## On its own, and with others

**On its own:** it needs an auth collection (default `users`) with sessions on, which is Payload's default, and your `canMasquerade`. It doesn't need any other plugin. Auditing is up to your `onStart` and `onStop`.

**Works with:**
- **Audit Trail:** call Audit Trail's `recordEvent` from `onStart` and `onStop` (with `masquerade` in its `actions`), and use `masqueraderOf(req)` in its `via` so a change made while masquerading says who really made it.
- **Hats:** as Hats' design describes, Hats' `blocked(req)` refuses switching while masquerading, and your `canMasquerade` refuses a switched session (`hatsStateOf(user).via`).

**Family:** It's part of the **Identity** family (a working draft): plugins designed to sit together for accounts and access.

## Install

```bash
npm install @extantape/payload-plugin-masq
```

```ts
import { masqPlugin } from '@extantape/payload-plugin-masq'

export default buildConfig({
  plugins: [
    masqPlugin({
      // Required. Who may masquerade (target absent = may they use masquerade at all).
      canMasquerade: ({ user, target }) => user.role === 'admin',
      onStart: async ({ req, masquerader, target, reason }) => {
        await req.payload.create({
          collection: 'audit-log',
          data: { action: 'masquerade-start', by: masquerader.id, user: target.id, reason },
          req,
        })
      },
      onStop: async ({ req, masqueraderId, targetId, expired, revoked }) => {
        /* … */
      },
    }),
  ],
})
```

Then run `payload generate:importmap`. Add the banner to your site layout (a Server
Component) so masqueraders see it outside the admin too:

```tsx
import { MasqueradeBanner } from '@extantape/payload-plugin-masq/rsc'

<MasqueradeBanner payload={payload} />
```

## Options

| Option | Default | |
|---|---|---|
| `canMasquerade` | (required) | `({ payload, user, target? }) => boolean`. No default: nobody can masquerade until you decide. |
| `collection` | `'users'` | Auth collection. |
| `duration` | `3600` | Seconds the borrowed session lasts. |
| `readOnly` | `true` | Refuse create, update and delete while masquerading. |
| `requireReason` | `false` | Ask for a reason; passed to `onStart`. |
| `labelField` | `'email'` | Name shown in the search and banner. |
| `searchFields` | `['email']` | Fields the search matches. |
| `startPath` | admin route | Where to go after starting. |
| `adminBanner` | `true` | Banner in the admin header. |
| `adminView` | `true` | Masquerade area and nav link. |
| `listColumn` | `true` | Masquerade column in the users list (added to `defaultColumns`). |
| `recheck` | | `({ payload, req, masquerader, target }) => boolean`, asked on every request a borrowed session makes, after `canMasquerade`. Only exactly `true` keeps the session; anything else, or a throw, ends it. Use it for checks `canMasquerade` doesn't make, such as a deny list. `req.user` isn't set yet. |
| `onStart`, `onStop` | | Audit hooks. `onStop` gets `revoked: true` when the per-request check ended the session. |
| `enabled` | `true` | |

## Endpoints

On the auth collection (`/api/users/…`): `POST /:id/masq` (start, body `{ reason? }`),
`POST /masq/stop` (return) and `GET /masq/search?q=` (admin search). All need a signed-in
user that `canMasquerade` allows. For how start answers a refusal, see **Refusals don't say who
exists** above.

## Acknowledgements

[payload-plugin-masquerade](https://github.com/manutepowa/payload-plugin-masquerade) came first
and is worth a look. We built this one because our direction differed in ways too large to
merge: a short borrowed session that ends on return, restore only for a still-valid masquerader,
an access-checked admin-only search, a banner on the site as well as the admin, and audit hooks.

## License

MIT
