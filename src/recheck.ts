import type { AuthStrategy, AuthStrategyFunctionArgs, Payload, PayloadRequest } from 'payload'

import { exactlyTrue, mayMasquerade } from './access.js'
import { type BorrowedClaim, borrowedClaims, masqOptions } from './state.js'
import type { MasqUser, ResolvedMasqOptions } from './types.js'

type WithSessions = MasqUser & { sessions?: { id: string }[] }

const load = (payload: Payload, collection: string, id: string) =>
  payload.findByID({ collection: collection as never, id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true }) as Promise<WithSessions | null>

/** The request path without trailing slashes. */
const pathOf = (url: string) => new URL(url, 'http://x').pathname.replace(/\/+$/, '')

/**
 * The same headers without the given borrowed tokens, so the strategies after this one (Payload's JWT strategy
 * among them) find no token to sign in with. The request's own headers are left as they are.
 */
function withoutTokens(payload: Payload, headers: Headers, claims: BorrowedClaim[]): Headers {
  const out = new Headers(headers)
  const name = `${payload.config?.cookiePrefix ?? 'payload'}-token`
  for (const c of claims) {
    if (c.from === 'header') out.delete('Authorization')
    else {
      const kept = (out.get('Cookie') ?? '')
        .split(';')
        .filter((part) => part.split('=')[0]!.trim() !== name)
        .join(';')
      if (kept.trim()) out.set('Cookie', kept)
      else out.delete('Cookie')
    }
  }
  return out
}

const MAX_TRIES = 3

/**
 * Removes the borrowed session from the target's sessions, reading the sessions again right before the write so
 * a sign-in that happened meanwhile is kept. In a transaction when the database supports one, so two requests
 * revoking the same session at once conflict and the loser reads again. Answers whether this call removed it,
 * so onStop is reported once. Throws when it can't be sure the session is gone.
 */
async function revoke(payload: Payload, collection: string, targetId: string | number, sid: string): Promise<boolean> {
  let last: unknown
  for (let i = 0; i < MAX_TRIES; i++) {
    const transactionID = (await payload.db.beginTransaction?.()) ?? undefined
    const req = (transactionID ? { transactionID } : {}) as PayloadRequest
    try {
      const fresh = (await payload.db.findOne({ collection, where: { id: { equals: targetId } }, req })) as WithSessions | null
      const sessions = fresh?.sessions ?? []
      const removed = sessions.some((s) => s.id === sid)
      if (removed) await payload.db.updateOne({ collection, id: targetId, data: { sessions: sessions.filter((s) => s.id !== sid) }, req, returning: false })
      if (transactionID) await payload.db.commitTransaction(transactionID)
      return removed
    } catch (err) {
      last = err
      if (transactionID) await payload.db.rollbackTransaction(transactionID).catch(() => undefined)
    }
  }
  throw last
}

async function recheckClaim(payload: Payload, opts: ResolvedMasqOptions, req: PayloadRequest | undefined, claim: BorrowedClaim, now: number) {
  if (!claim.sid || !claim.id || (claim.exp !== null && claim.exp <= now)) return
  const target = await load(payload, opts.collection, claim.id)
  if (!target?.sessions?.some((s) => s.id === claim.sid)) return
  const masquerader = await load(payload, opts.collection, claim.by)
  const allowed =
    masquerader !== null &&
    (await mayMasquerade(opts, { payload, user: masquerader, target })) &&
    (!opts.recheck || (await exactlyTrue(() => opts.recheck!({ payload, req, masquerader, target }))))
  if (allowed) return
  if (!(await revoke(payload, opts.collection, target.id, claim.sid))) return
  try {
    await opts.onStop?.({ req: req as PayloadRequest, masqueraderId: claim.by, targetId: String(target.id), expired: false, restored: false, revoked: true })
  } catch (err) {
    payload.logger.error({ err, msg: 'payload-plugin-masq: onStop failed after a revoked masquerade' })
  }
}

/**
 * Rechecks every borrowed session on every request. It runs before Payload's own JWT strategy and never signs
 * anyone in itself. When the masquerader may no longer masquerade as the target (canMasquerade, and recheck if
 * set, no longer answer exactly true), or either account is gone, it deletes the borrowed session from the
 * target's sessions, so the JWT strategy that follows refuses the token, from a cookie or a header alike.
 *
 * It fails closed: if the recheck itself fails (a read or the delete throws), the borrowed token is taken out
 * of the headers the later strategies read, so the request runs signed out.
 */
export const recheckStrategy: AuthStrategy = {
  name: 'masq-recheck',
  authenticate: async (args: AuthStrategyFunctionArgs) => {
    const { headers, payload, req } = args
    let claims: BorrowedClaim[] = []
    try {
      claims = borrowedClaims(payload, headers)
      if (!claims.length) return { user: null }
      const opts = masqOptions(payload)
      if (!opts) throw new Error('masq options are missing')
      // The stop endpoint ends the borrowed session itself and reports it once through onStop.
      if (req?.url && req.method === 'POST' && pathOf(req.url) === `${opts.apiRoute}/${opts.collection}/masq/stop`) return { user: null }
      const now = Date.now() / 1000
      const failed: BorrowedClaim[] = []
      // One recheck per borrowed session, even when its token comes in the cookie and the header both.
      const outcome = new Map<string, boolean>()
      for (const claim of claims) {
        const key = JSON.stringify([claim.by, claim.id, claim.sid, claim.exp])
        if (!outcome.has(key)) {
          try {
            await recheckClaim(payload, opts, req as PayloadRequest | undefined, claim, now)
            outcome.set(key, true)
          } catch (err) {
            payload.logger.error({ err, msg: 'payload-plugin-masq: could not recheck a borrowed session; this request runs signed out' })
            outcome.set(key, false)
          }
        }
        if (!outcome.get(key)) failed.push(claim)
      }
      if (failed.length) args.headers = withoutTokens(payload, headers, failed)
    } catch (err) {
      payload.logger.error({ err, msg: 'payload-plugin-masq: could not recheck a borrowed session; this request runs signed out' })
      if (claims.length) args.headers = withoutTokens(payload, headers, claims)
    }
    return { user: null }
  },
}
