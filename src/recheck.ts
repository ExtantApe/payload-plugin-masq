import type { AuthStrategy, Payload, PayloadRequest } from 'payload'

import { exactlyTrue, mayMasquerade } from './access.js'
import { borrowedClaims, masqOptions } from './state.js'
import type { MasqUser } from './types.js'

type WithSessions = MasqUser & { sessions?: { id: string }[] }

const load = (payload: Payload, collection: string, id: string) =>
  payload.findByID({ collection: collection as never, id, depth: 0, overrideAccess: true, showHiddenFields: true, disableErrors: true }) as Promise<WithSessions | null>

/**
 * Rechecks every borrowed session on every request. It runs before Payload's own JWT strategy and never signs
 * anyone in itself. When the masquerader may no longer masquerade as the target (canMasquerade, and recheck if
 * set, no longer answer exactly true), or either account is gone, it deletes the borrowed session from the
 * target's sessions, so the JWT strategy that follows refuses the token, from a cookie or a header alike.
 */
export const recheckStrategy: AuthStrategy = {
  name: 'masq-recheck',
  authenticate: async ({ headers, payload, req }) => {
    try {
      const opts = masqOptions(payload)
      if (!opts) return { user: null }
      // The stop endpoint ends the borrowed session itself and reports it once through onStop.
      if (req?.url && req.method === 'POST' && new URL(req.url, 'http://x').pathname === `${opts.apiRoute}/${opts.collection}/masq/stop`) return { user: null }
      const now = Date.now() / 1000
      for (const claim of borrowedClaims(payload, headers)) {
        if (!claim.sid || !claim.id || (claim.exp !== null && claim.exp <= now)) continue
        const target = await load(payload, opts.collection, claim.id)
        if (!target?.sessions?.some((s) => s.id === claim.sid)) continue
        const masquerader = await load(payload, opts.collection, claim.by)
        const allowed =
          masquerader !== null &&
          (await mayMasquerade(opts, { payload, user: masquerader, target })) &&
          (!opts.recheck || (await exactlyTrue(() => opts.recheck!({ payload, req: req as PayloadRequest | undefined, masquerader, target }))))
        if (allowed) continue
        await payload.db.updateOne({
          collection: opts.collection,
          id: target.id,
          data: { sessions: target.sessions.filter((s) => s.id !== claim.sid) },
          returning: false,
        })
        try {
          await opts.onStop?.({ req: req as PayloadRequest, masqueraderId: claim.by, targetId: String(target.id), expired: false, restored: false, revoked: true })
        } catch (err) {
          payload.logger.error({ err, msg: 'payload-plugin-masq: onStop failed after a revoked masquerade' })
        }
      }
    } catch (err) {
      payload.logger.error({ err, msg: 'payload-plugin-masq: could not recheck a borrowed session' })
    }
    return { user: null }
  },
}
