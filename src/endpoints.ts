import { addDataAndFileToRequest, APIError, getFieldsToSign, jwtSign, type Endpoint, type PayloadRequest, type Where } from 'payload'
import { addSessionToUser, parseCookies } from 'payload/shared'

import { BORROWED_CLAIM, borrowedClaim, cookie, encodeState, isMasquerading, masqOptions, masqStateOf, RETURN_COOKIE, sessionsOn, STATE_COOKIE } from './state.js'
import { mayMasquerade } from './access.js'
import { revoke } from './revoke.js'
import type { MasqUser } from './types.js'

const STATE_SECONDS = 24 * 60 * 60

const json = (body: unknown, cookies: string[] = [], status = 200) => {
  const headers = new Headers({ 'Content-Type': 'application/json' })
  for (const c of cookies) headers.append('Set-Cookie', c)
  return new Response(JSON.stringify(body), { status, headers })
}

const tokenCookie = (req: PayloadRequest) => `${req.payload.config.cookiePrefix}-token`

/** The signed-in user of the masquerade collection, or a 403. */
function signedIn(req: PayloadRequest): MasqUser {
  const { collection } = masqOptions(req.payload)
  if (!req.user || req.user.collection !== collection) throw new APIError('Sign in first.', 401, undefined, true)
  return req.user as unknown as MasqUser
}

/** POST /api/<collection>/:id/masq  { reason? } */
export const startEndpoint: Endpoint = {
  path: '/:id/masq',
  method: 'post',
  handler: async (req) => {
    const opts = masqOptions(req.payload)
    const user = signedIn(req)
    // Without sessions a borrowed token can't be ended early, so none is handed out.
    if (!sessionsOn(req.payload, opts.collection)) throw new APIError('Masquerade needs sessions turned on.', 500, undefined, true)
    if (isMasquerading(req.payload, req.headers)) throw new APIError('Stop masquerading first.', 400, undefined, true)
    const own = parseCookies(req.headers).get(tokenCookie(req))
    if (!own) throw new APIError('Masquerade needs a browser sign-in.', 400, undefined, true)
    const id = String(req.routeParams?.id ?? '')
    if (!id || id === String(user.id)) throw new APIError('Choose another user.', 400, undefined, true)
    await addDataAndFileToRequest(req)
    const reason = typeof req.data?.reason === 'string' ? req.data.reason.trim().slice(0, 500) || null : null
    if (opts.requireReason && !reason) throw new APIError('Say why you are masquerading.', 400, undefined, true)

    const target = (await req.payload.findByID({
      collection: opts.collection as never,
      id,
      depth: 0,
      overrideAccess: true,
      showHiddenFields: true,
      disableErrors: true,
      req,
    })) as MasqUser | null
    if (!target) throw new APIError('User not found.', 404, undefined, true)
    if (!(await mayMasquerade(opts, { payload: req.payload, user, target }))) throw new APIError('You may not masquerade as this user.', 403, undefined, true)

    const collectionConfig = req.payload.collections[opts.collection as never]!.config
    const { sid } = await addSessionToUser({ collectionConfig, payload: req.payload, req, user: target as never })
    const { token } = await jwtSign({
      // Marked as borrowed, so it stays read-only and can't be refreshed even without the state cookie.
      fieldsToSign: { ...getFieldsToSign({ collectionConfig, email: String(target.email ?? ''), sid, user: target as never }), [BORROWED_CLAIM]: String(user.id) },
      secret: req.payload.secret,
      tokenExpiration: opts.duration,
    })
    const now = Date.now()
    const state = { by: String(user.id), as: id, at: new Date(now).toISOString(), until: new Date(now + opts.duration * 1000).toISOString(), sid }
    await opts.onStart?.({ req, masquerader: user, target, reason })
    return json({ ok: true, redirect: opts.startPath }, [
      cookie(req.payload, opts.collection, tokenCookie(req), token, opts.duration),
      // The masquerader's own token goes back only to the stop endpoint.
      cookie(req.payload, opts.collection, RETURN_COOKIE, own, STATE_SECONDS, `${opts.apiRoute}/${opts.collection}/masq/stop`),
      cookie(req.payload, opts.collection, STATE_COOKIE, encodeState(req.payload.secret, state), STATE_SECONDS),
    ])
  },
}

/** A user id from a cookie, as the collection stores it: a number where the ids are numbers. */
function idOf(req: PayloadRequest, id: string): number | string {
  const type = req.payload.collections[masqOptions(req.payload).collection as never]?.customIDType ?? req.payload.db.defaultIDType
  return type === 'number' ? Number(id) : id
}

/** POST /api/<collection>/masq/stop: end the borrowed session and restore the masquerader's own. */
export const stopEndpoint: Endpoint = {
  path: '/masq/stop',
  method: 'post',
  handler: async (req) => {
    const opts = masqOptions(req.payload)
    const state = masqStateOf(req.payload, req.headers)
    // Our own writes (and onStop's) are allowed even in read-only mode.
    req.context = { ...req.context, masqInternal: true }
    const own = parseCookies(req.headers).get(RETURN_COOKIE)
    const stopPath = `${opts.apiRoute}/${opts.collection}/masq/stop`
    const clear = [cookie(req.payload, opts.collection, RETURN_COOKIE, '', -1, stopPath), cookie(req.payload, opts.collection, STATE_COOKIE, '', -1)]

    const clearAll = [...clear, cookie(req.payload, opts.collection, tokenCookie(req), '', -1)]
    const login = `${opts.adminRoute}/login`

    // The borrowed session this request is signed in with, if any. Only a genuine claim counts, on the token
    // that signs in the very user and session this request is authenticated as.
    const borrowed = req.user as (MasqUser & { _sid?: string; collection?: string }) | null
    const claim = borrowed?.collection === opts.collection ? borrowedClaim(req.payload, req.headers, { userId: String(borrowed.id), sid: borrowed._sid }) : null
    const inUse = claim && borrowed?._sid && claim.id === String(borrowed.id) ? { id: borrowed.id, sid: borrowed._sid, by: claim.by } : null

    // The one session this stop ends. With the state cookie it is the session the cookie names, by its id, and
    // never another one that happens to be signed in. A cookie from before the state carried the id names the
    // signed-in borrowed session only when masquerader and target both match. With no state cookie it is the
    // signed-in borrowed session.
    const sameMasquerade = Boolean(state && inUse && String(inUse.id) === state.as && inUse.by === state.by)
    const ending: { id: number | string; sid: string } | null = !state
      ? inUse
      : state.sid
        ? { id: sameMasquerade && inUse!.sid === state.sid ? inUse!.id : idOf(req, state.as), sid: state.sid }
        : sameMasquerade
          ? inUse
          : null
    // Whether this request was signed in with that very session, so it was alive a moment ago.
    const wasAlive = Boolean(ending && inUse && ending.sid === inUse.sid && String(ending.id) === String(inUse.id))

    // The delete reads the sessions again in a transaction, and answers whether this call removed the session.
    let removed = false
    if (ending) {
      try {
        removed = await revoke(req.payload, opts.collection, ending.id, ending.sid)
      } catch (err) {
        // Fail closed. The borrowed session may still be alive, so nothing here claims it ended: no onStop, no
        // success, and the masquerader's own token is not handed back while the borrowed one might still work.
        // The browser loses every masquerade cookie and goes to the login page. The per-request recheck and the
        // session's own hour still bound the borrowed token.
        req.payload.logger.error({
          err,
          masqueraderId: state?.by ?? inUse?.by,
          targetId: String(ending.id),
          msg: 'payload-plugin-masq: could not end a borrowed session on stop; it may still be alive until its hour runs out. The browser was signed out.',
        })
        return json(
          { ok: false, restored: false, redirect: login, errors: [{ message: 'The masquerade could not be confirmed as ended. You have been signed out. Sign in again.' }] },
          clearAll,
          500,
        )
      }
    }

    // Restore only a still-valid token of the same masquerader who may still masquerade.
    const restored = state && own ? await req.payload.auth({ headers: new Headers({ Authorization: `JWT ${own}` }) }).catch(() => null) : null
    const user = (restored?.user ?? null) as MasqUser | null
    const ok = Boolean(state && user && String(user.id) === state.by && (await mayMasquerade(opts, { payload: req.payload, user: user! })))

    // One report per ended session. A request that was signed in with the session but didn't remove it lost to
    // another request ending it at the same moment, and that one reports.
    if (state) {
      const hourOver = Date.now() >= Date.parse(state.until)
      // Expired only when the session the state names had really ended before this stop: it was already gone,
      // or its hour was over. With no session named and none ended, only the hour can say so.
      const expired = wasAlive ? false : ending ? !removed || hourOver : hourOver
      if (!wasAlive || removed) await opts.onStop?.({ req, masqueraderId: state.by, targetId: state.as, expired, restored: ok })
    } else if (inUse && removed) await opts.onStop?.({ req, masqueraderId: inUse.by, targetId: String(inUse.id), expired: false, restored: false })
    if (!ok) return json({ ok: true, restored: false, redirect: login }, clearAll)
    const seconds = req.payload.collections[opts.collection as never]!.config.auth.tokenExpiration
    return json({ ok: true, restored: true, redirect: `${opts.adminRoute}/collections/${opts.collection}/${state!.as}` }, [
      ...clear,
      cookie(req.payload, opts.collection, tokenCookie(req), own!, seconds),
    ])
  },
}

/**
 * GET /api/<collection>/masq/search?q=&page=: the admin user search. Only for
 * people allowed to masquerade at all, and it reads with their own access, so it
 * never shows a user they could not already see. Lists only users they may
 * masquerade as.
 */
export const searchEndpoint: Endpoint = {
  path: '/masq/search',
  method: 'get',
  handler: async (req) => {
    const opts = masqOptions(req.payload)
    const user = signedIn(req)
    if (!(await mayMasquerade(opts, { payload: req.payload, user }))) throw new APIError('Not allowed.', 403, undefined, true)
    const q = String(req.searchParams?.get('q') ?? '').trim().slice(0, 100)
    const page = Math.max(1, Number(req.searchParams?.get('page')) || 1)
    const where: Where = {
      and: [{ id: { not_equals: user.id } }, ...(q ? [{ or: opts.searchFields.map((f) => ({ [f]: { like: q } })) }] : [])],
    }
    const found = await req.payload.find({
      collection: opts.collection as never,
      where,
      page,
      limit: 20,
      depth: 0,
      sort: opts.labelField,
      overrideAccess: false,
      user: req.user,
      req,
    })
    const docs = await Promise.all(
      (found.docs as MasqUser[]).map(async (d) => ({
        id: String(d.id),
        label: String(d[opts.labelField] ?? d.email ?? d.id),
        email: d.email ?? null,
        allowed: await mayMasquerade(opts, { payload: req.payload, user, target: d }),
      })),
    )
    return json({ docs, page: found.page, totalPages: found.totalPages, totalDocs: found.totalDocs })
  },
}
