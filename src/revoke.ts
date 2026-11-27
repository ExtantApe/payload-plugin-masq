import crypto from 'node:crypto'

import type { Payload, PayloadRequest } from 'payload'

import { masqOptions } from './state.js'

type Session = { id: string; createdAt?: Date | string; expiresAt: Date | string }
type WithSessions = { sessions?: Session[] }

/** How often a change to a target's sessions is tried before giving up. */
export const MAX_TRIES = 12
const BASE_WAIT_MS = 20
const MAX_WAIT_MS = 250

export const NO_TRANSACTIONS_MESSAGE =
  'payload-plugin-masq: the database adapter gave no transaction, and masq changes sessions only inside one. Turn transactions on in the database adapter (MongoDB needs a replica set), or set allowNoTransactions: true, which is unsafe when requests overlap.'

/** A wait that grows with each try and is picked at random below its cap, so requests that collided spread out. */
const backoff = (tries: number) => new Promise<void>((r) => setTimeout(r, Math.random() * Math.min(MAX_WAIT_MS, BASE_WAIT_MS * 2 ** tries)))

class NoTransactions extends Error {}

type Attempt<T> = { result: T; wrote: boolean }

/**
 * Runs one read-then-write on a target's sessions inside a transaction, and tries again after a short random
 * wait when it fails, because two requests changing the same user at once conflict and the loser must read
 * again. Beginning the transaction is part of each try. Without a transaction it refuses, unless the host set
 * `allowNoTransactions`.
 *
 * `uncertain` is true when an earlier try wrote and its commit then threw, so that write may or may not have
 * landed before the try that answered.
 */
async function inTransaction<T>(payload: Payload, work: (req: PayloadRequest) => Promise<Attempt<T>>): Promise<{ result: T; uncertain: boolean }> {
  let last: unknown
  let uncertain = false
  for (let i = 0; i < MAX_TRIES; i++) {
    if (i) await backoff(i - 1)
    let transactionID: number | string | undefined
    let committing = false
    let wrote = false
    try {
      transactionID = (await payload.db.beginTransaction?.()) ?? undefined
      if (!transactionID && !masqOptions(payload)?.allowNoTransactions) throw new NoTransactions(NO_TRANSACTIONS_MESSAGE)
      const attempt = await work((transactionID ? { transactionID } : {}) as PayloadRequest)
      wrote = attempt.wrote
      committing = true
      if (transactionID) await payload.db.commitTransaction(transactionID)
      return { result: attempt.result, uncertain }
    } catch (err) {
      if (err instanceof NoTransactions) throw err
      last = err
      if (committing && wrote) uncertain = true
      if (transactionID) await payload.db.rollbackTransaction(transactionID).catch(() => undefined)
    }
  }
  throw last
}

const read = async (payload: Payload, collection: string, targetId: number | string, req: PayloadRequest) =>
  (await payload.db.findOne({ collection, where: { id: { equals: targetId } }, req })) as WithSessions | null

/**
 * Removes the borrowed session from the target's sessions, reading the sessions again right before the write so
 * a sign-in that happened meanwhile is kept. In a transaction, so two requests changing the same user's sessions
 * at once conflict and the loser reads again. Answers whether this call removed it, so onStop is reported once.
 * Throws when it can't be sure the session is gone.
 *
 * Both the per-request recheck and the stop endpoint end a borrowed session through here.
 */
export async function revoke(payload: Payload, collection: string, targetId: string | number, sid: string): Promise<boolean> {
  const { result: removed, uncertain } = await inTransaction(payload, async (req) => {
    const sessions = (await read(payload, collection, targetId, req))?.sessions ?? []
    const found = sessions.some((s) => s.id === sid)
    if (found) await payload.db.updateOne({ collection, id: targetId, data: { sessions: sessions.filter((s) => s.id !== sid) }, req, returning: false })
    return { result: found, wrote: found }
  })
  // A commit that threw may still have landed. If the session is gone on the next read, nobody can tell whether
  // this call or another one removed it, so the caller may report no onStop for it. Say so in the log.
  if (!removed && uncertain)
    payload.logger.error({
      targetId: String(targetId),
      msg: 'payload-plugin-masq: a borrowed session is gone, but the commit that removed it gave no answer, so onStop may not have been reported for it.',
    })
  return removed
}

/**
 * Adds a new session to the target, the way Payload's own sign-in does (expired sessions dropped, `updatedAt`
 * left alone), but with the sessions read again inside a transaction right before the write. A session that was
 * ended while the start was being checked therefore stays ended, and one added meanwhile is kept. Answers the new
 * session's id, or null when the target no longer exists.
 */
export async function addSession(payload: Payload, collection: string, targetId: string | number, seconds: number): Promise<string | null> {
  const { result } = await inTransaction(payload, async (req) => {
    const fresh = await read(payload, collection, targetId, req)
    if (!fresh) return { result: null, wrote: false }
    const now = Date.now()
    const sid = crypto.randomUUID()
    const live = (fresh.sessions ?? []).filter((s) => new Date(s.expiresAt).getTime() > now)
    const sessions = [...live, { id: sid, createdAt: new Date(now), expiresAt: new Date(now + seconds * 1000) }]
    await payload.db.updateOne({ collection, id: targetId, data: { sessions, updatedAt: null }, req, returning: false })
    return { result: sid, wrote: true }
  })
  return result
}

/**
 * Proves at start-up that the database really runs a transaction: one is begun, a read runs inside it, and it is
 * committed. A standalone MongoDB hands out a transaction and then refuses the first read in it, so beginning one
 * is not proof enough.
 */
export async function assertTransactions(payload: Payload, collection: string): Promise<void> {
  let reason = 'the adapter gave no transaction'
  try {
    const transactionID = (await payload.db.beginTransaction?.()) ?? undefined
    if (transactionID) {
      try {
        await payload.db.findOne({ collection, where: { id: { exists: true } }, req: { transactionID } as PayloadRequest })
        await payload.db.commitTransaction(transactionID)
        return
      } catch (err) {
        await payload.db.rollbackTransaction(transactionID).catch(() => undefined)
        throw err
      }
    }
  } catch (err) {
    reason = err instanceof Error ? err.message : String(err)
  }
  throw new Error(
    `payload-plugin-masq: the database can't run transactions (${reason}). Masq starts and ends a borrowed session inside a transaction, so that requests arriving together can't undo each other. Turn transactions on in the database adapter (MongoDB needs a replica set), or set allowNoTransactions: true to run without them, which is unsafe when requests overlap.`,
  )
}
