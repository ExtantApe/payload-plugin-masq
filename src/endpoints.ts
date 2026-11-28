import { addDataAndFileToRequest, APIError, getFieldsToSign, jwtSign, type Endpoint, type PayloadRequest, type Where } from 'payload'
import { addSessionToUser, parseCookies } from 'payload/shared'

import { BORROWED_CLAIM, borrowedClaim, cookie, encodeState, isMasquerading, masqOptions, masqStateOf, RETURN_COOKIE, sessionsOn, STATE_COOKIE } from './state.js'
import { mayMasquerade } from './access.js'
import { ensureGuards } from './guard.js'
import type { MasqUser, ResolvedMasqOptions } from './types.js'

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

/**
 * The account a masquerade's target id names, or null. A lookup that fails (an id the database can't read, a
 * hook that throws) counts as no user, so start's answer is the same as for an id nobody has. So does an
 * account that comes back without a usable id of its own.
 */
async function loadTarget(req: PayloadRequest, collection: string, id: string): Promise<MasqUser | null> {
  try {
    const found = (await req.payload.findByID({
      collection: collection as never,
      id,
      depth: 0,
      overrideAccess: true,
      showHiddenFields: true,
      disableErrors: true,
      req,
    })) as MasqUser | null
    const foundId: unknown = found?.id
    return (typeof foundId === 'string' && foundId) || Number.isFinite(foundId) ? found : null
  } catch (err) {
    req.payload.logger.error({ err, msg: 'payload-plugin-masq: could not load the user to masquerade as' })
    return null
  }
}

/** Whether the signed-in user's own read access finds this account. An error is a no. */
async function canRead(req: PayloadRequest, collection: string, id: string): Promise<boolean> {
  try {
    return Boolean(
      await req.payload.findByID({ collection: collection as never, id, depth: 0, overrideAccess: false, user: req.user, disableErrors: true, req }),
    )
  } catch {
    return false
  }
}

/**
 * Why start is refused, without saying whether an account exists to anyone who couldn't already know.
 * Someone who may not use masquerade at all (`canMasquerade` with no target) always gets the same 403.
 * Someone who may gets "not found", for a missing account and equally for a refused one their own read
 * access doesn't find, and the 403 only for a refused account they can read.
 */
async function startRefusal(opts: ResolvedMasqOptions, req: PayloadRequest, user: MasqUser, target: MasqUser | null): Promise<Error> {
  const notFound = (await mayMasquerade(opts, { payload: req.payload, user })) && !(target && (await canRead(req, opts.collection, String(target.id))))
  return notFound
    ? new APIError('User not found.', 404, undefined, true)
    : new APIError('You may not masquerade as this user.', 403, undefined, true)
}

/** POST /api/<collection>/:id/masq  { reason? } */
export const startEndpoint: Endpoint = {
  path: '/:id/masq',
  method: 'post',
  handler: async (req) => {
    const opts = masqOptions(req.payload)
    const user = signedIn(req)
    // A borrowed session is handed out only while read-only masquerade is confirmed on everything Payload built.
    const guards = ensureGuards(req.payload)
    if (!guards.ok) {
      req.payload.logger.error({ msg: `payload-plugin-masq: masquerade is unavailable; read-only masquerade is not in place on ${guards.missing.join(', ')}` })
      throw new APIError('Masquerade is unavailable right now. The server log says why.', 503, undefined, true)
    }
    // Without sessions a borrowed token can't be ended early, so none is handed out.
    if (!sessionsOn(req.payload, opts.collection)) throw new APIError('Masquerade needs sessions turned on.', 500, undefined, true)
    if (isMasquerading(req.payload, req.headers)) throw new APIError('Stop masquerading first.', 400, undefined, true)
    const own = parseCookies(req.headers).get(tokenCookie(req))
    if (!own) throw new APIError('Masquerade needs a browser sign-in.', 400, undefined, true)
    // The id as the caller spelled it. It only finds the account: a database can read several spellings as one
    // id (hex in either case; "01" for 1), so who the account is comes from the account found.
    const asked = String(req.routeParams?.id ?? '')
    const chooseAnother = () => new APIError('Choose another user.', 400, undefined, true)
    if (!asked || asked === String(user.id)) throw chooseAnother()
    await addDataAndFileToRequest(req)
    const reason = typeof req.data?.reason === 'string' ? req.data.reason.trim().slice(0, 500) || null : null
    if (opts.requireReason && !reason) throw new APIError('Say why you are masquerading.', 400, undefined, true)

    const target = await loadTarget(req, opts.collection, asked)
    if (target && String(target.id) === String(user.id)) throw chooseAnother()
    if (!target || !(await mayMasquerade(opts, { payload: req.payload, user, target }))) throw await startRefusal(opts, req, user, target)

    const collectionConfig = req.payload.collections[opts.collection as never]!.config
    const { sid } = await addSessionToUser({ collectionConfig, payload: req.payload, req, user: target as never })
    const { token } = await jwtSign({
      // Marked as borrowed, so it stays read-only and can't be refreshed even without the state cookie.
      fieldsToSign: { ...getFieldsToSign({ collectionConfig, email: String(target.email ?? ''), sid, user: target as never }), [BORROWED_CLAIM]: String(user.id) },
      secret: req.payload.secret,
      tokenExpiration: opts.duration,
    })
    const now = Date.now()
    const state = { by: String(user.id), as: String(target.id), at: new Date(now).toISOString(), until: new Date(now + opts.duration * 1000).toISOString() }
    await opts.onStart?.({ req, masquerader: user, target, reason })
    return json({ ok: true, redirect: opts.startPath }, [
      cookie(req.payload, opts.collection, tokenCookie(req), token, opts.duration),
      // The masquerader's own token goes back only to the stop endpoint.
      cookie(req.payload, opts.collection, RETURN_COOKIE, own, STATE_SECONDS, `${opts.apiRoute}/${opts.collection}/masq/stop`),
      cookie(req.payload, opts.collection, STATE_COOKIE, encodeState(req.payload.secret, state), STATE_SECONDS),
    ])
  },
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

    // End the borrowed session if it is still alive: named by the state cookie, or, if that
    // cookie is gone, by the borrowed token's own claim.
    const borrowed = req.user as (MasqUser & { _sid?: string; collection?: string }) | null
    // Only a genuine claim, on the token that signs in the very user this request is authenticated as.
    const claim = borrowed ? borrowedClaim(req.payload, req.headers, { userId: String(borrowed.id), sid: borrowed._sid }) : null
    const claimedBy = claim && borrowed && claim.id === String(borrowed.id) ? claim.by : null
    // A state cookie set before an upgrade can spell the target's id differently from the account's own id. Only
    // then, and only for the same masquerader, is the account looked up: it matches if its own id is the claim's.
    let targetId = state?.as
    if (state && borrowed?.collection === opts.collection && claimedBy === state.by && claim!.id !== state.as) {
      const found = await loadTarget(req, opts.collection, state.as)
      if (found && String(found.id) === claim!.id) targetId = claim!.id
    }
    // With the state cookie, only the borrowed session it names: same target and same masquerader.
    const live = Boolean(borrowed?.collection === opts.collection && claimedBy && (!state || (claim!.id === targetId && claimedBy === state.by)))
    if (live && borrowed?._sid) {
      const doc = (await req.payload.findByID({ collection: opts.collection as never, id: borrowed.id, depth: 0, overrideAccess: true, showHiddenFields: true, req })) as {
        sessions?: { id: string }[]
      }
      await req.payload.db.updateOne({
        collection: opts.collection,
        id: borrowed.id,
        data: { sessions: (doc.sessions ?? []).filter((s) => s.id !== borrowed._sid) },
        req,
        returning: false,
      })
    }

    // Restore only a still-valid token of the same masquerader who may still masquerade.
    const restored = state && own ? await req.payload.auth({ headers: new Headers({ Authorization: `JWT ${own}` }) }).catch(() => null) : null
    const user = (restored?.user ?? null) as MasqUser | null
    const ok = Boolean(state && user && String(user.id) === state.by && (await mayMasquerade(opts, { payload: req.payload, user: user! })))
    if (state) await opts.onStop?.({ req, masqueraderId: state.by, targetId: targetId!, expired: !live, restored: ok })
    else if (live && claimedBy) await opts.onStop?.({ req, masqueraderId: claimedBy, targetId: String(borrowed!.id), expired: false, restored: false })
    if (!ok) return json({ ok: true, restored: false, redirect: `${opts.adminRoute}/login` }, [...clear, cookie(req.payload, opts.collection, tokenCookie(req), '', -1)])
    const seconds = req.payload.collections[opts.collection as never]!.config.auth.tokenExpiration
    return json({ ok: true, restored: true, redirect: `${opts.adminRoute}/collections/${opts.collection}/${targetId}` }, [
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
