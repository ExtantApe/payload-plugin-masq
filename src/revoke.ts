import type { Payload, PayloadRequest } from 'payload'

type WithSessions = { sessions?: { id: string }[] }

const MAX_TRIES = 3

/**
 * Removes the borrowed session from the target's sessions, reading the sessions again right before the write so
 * a sign-in that happened meanwhile is kept. In a transaction when the database supports one, so two requests
 * revoking the same session at once conflict and the loser reads again. Answers whether this call removed it,
 * so onStop is reported once. Throws when it can't be sure the session is gone.
 *
 * Both the per-request recheck and the stop endpoint end a borrowed session through here.
 */
export async function revoke(payload: Payload, collection: string, targetId: string | number, sid: string): Promise<boolean> {
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
