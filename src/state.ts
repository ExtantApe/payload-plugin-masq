import crypto from 'node:crypto'

import type { Payload, PayloadRequest } from 'payload'
import { generateCookie, parseCookies } from 'payload/shared'

import type { MasqState, ResolvedMasqOptions } from './types.js'

export const STATE_COOKIE = 'payload-masq'
export const RETURN_COOKIE = 'payload-masq-return'

const mac = (secret: string, body: string) => crypto.createHmac('sha256', secret).update(`masq:${body}`).digest('base64url')

export function encodeState(secret: string, state: MasqState): string {
  const body = Buffer.from(JSON.stringify(state)).toString('base64url')
  return `${body}.${mac(secret, body)}`
}

/** The state from a signed cookie value, or null if missing, forged or malformed. */
export function decodeState(secret: string, raw: string | null | undefined): MasqState | null {
  if (!raw) return null
  const [body, sig] = raw.split('.')
  if (!body || !sig) return null
  const expected = Buffer.from(mac(secret, body))
  const given = Buffer.from(sig)
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null
  try {
    const s = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Partial<MasqState>
    if (!s.by || !s.as || !s.at || !s.until) return null
    // A cookie issued before the state carried the session id has none; any other shape of it is dropped.
    const { sid, ...rest } = s
    return (typeof sid === 'string' && sid ? { ...rest, sid } : rest) as MasqState
  } catch {
    return null
  }
}

/** The active masquerade of a request (from its cookies), if any. */
export const masqStateOf = (payload: Payload, headers: Headers | null | undefined) =>
  headers ? decodeState(payload.secret, parseCookies(headers).get(STATE_COOKIE)) : null

/** Claim that marks a borrowed session's token, with the masquerader's id. */
export const BORROWED_CLAIM = 'masqBy'

/**
 * The claim of a borrowed masquerade session in the request's Payload token (cookie or
 * Authorization header): the masquerader (`by`) and the account the token signs in as
 * (`id`). Only a token signed with Payload's secret counts, checked the way Payload checks
 * its own JWTs (HS256), so a forged claim is ignored.
 */
export type BorrowedClaim = { by: string; id: string; sid: string | null; exp: number | null; token: string; from: 'cookie' | 'header' }

/**
 * Every value the request carries for the cookie `name`, read at least as loosely as Payload's own JWT strategy
 * reads it: names trimmed, every occurrence kept (Payload keeps the last), each value both as sent and URI-decoded.
 */
function cookieValues(headers: Headers, name: string): string[] {
  const out: string[] = []
  for (const part of (headers.get('Cookie') ?? '').split(';')) {
    const [key, ...rest] = part.split('=')
    if (key?.trim() !== name) continue
    const raw = rest.join('=')
    out.push(raw)
    try {
      const decoded = decodeURI(raw)
      if (decoded !== raw) out.push(decoded)
    } catch {
      // Payload skips a value it can't decode; the raw value is still checked.
    }
  }
  return out
}

/** Base64url decoded the way jose decodes it (Node's decoder, which skips whitespace, padding and other stray characters). */
const b64 = (s: string) => Buffer.from(s, 'base64url')

/**
 * Every genuine borrowed claim in the request, cookie first, then the Authorization header. It reads tokens at
 * least as loosely as Payload's JWT strategy and jose do (padding or whitespace in the signature, spaces around
 * the cookie name, any letter case in the scheme), so no spelling Payload signs in with escapes the checks.
 */
export function borrowedClaims(payload: Payload, headers: Headers | null | undefined): BorrowedClaim[] {
  if (!headers || !payload.secret) return []
  const auth = headers.get('Authorization') ?? ''
  const scheme = /^\s*(?:jwt|bearer)\s+/i.exec(auth)
  const tokens: [string, 'cookie' | 'header'][] = [
    ...cookieValues(headers, `${payload.config?.cookiePrefix ?? 'payload'}-token`).map((t) => [t, 'cookie'] as [string, 'cookie']),
    ...(scheme ? [[auth.slice(scheme[0].length), 'header'] as [string, 'header']] : []),
  ]
  const out: BorrowedClaim[] = []
  const seen = new Set<string>()
  for (const [token, from] of tokens) {
    const [head, body, sig] = token.split('.')
    if (!head || !body || !sig) continue
    // The same signed token repeated (or its raw and decoded copies) counts once.
    const key = `${from} ${head}.${body}`
    if (seen.has(key)) continue
    const expected = crypto.createHmac('sha256', payload.secret).update(`${head}.${body}`).digest()
    const given = b64(sig)
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) continue
    seen.add(key)
    try {
      if ((JSON.parse(b64(head).toString('utf8')) as { alg?: string }).alg !== 'HS256') continue
      const claims = JSON.parse(b64(body).toString('utf8')) as Record<string, unknown>
      const by = claims[BORROWED_CLAIM]
      if (typeof by === 'string' && by)
        out.push({
          by,
          id: String(claims.id ?? ''),
          sid: typeof claims.sid === 'string' ? claims.sid : null,
          exp: typeof claims.exp === 'number' ? claims.exp : null,
          token,
          from,
        })
    } catch {
      // Not a JWT we can read: not a borrowed session.
    }
  }
  return out
}

/**
 * The first borrowed claim, or with `session`, the claim on the very token that signed in: the same user and the
 * same session id. A second token for the same user (another masquerader's, or the user's own) is never picked.
 */
export function borrowedClaim(
  payload: Payload,
  headers: Headers | null | undefined,
  session?: { userId: string; sid: string | undefined },
): { by: string; id: string } | null {
  const all = borrowedClaims(payload, headers)
  const c = session === undefined ? all[0] : session.sid ? all.find((x) => x.id === session.userId && x.sid === session.sid) : undefined
  return c ? { by: c.by, id: c.id } : null
}

/**
 * Whether the masquerade collection, as Payload finally built it, keeps sessions. Payload turns sessions off for
 * any falsy useSessions, and another plugin or the host can change it after masq has run, so this reads the
 * built config and only exactly true counts.
 */
export const sessionsOn = (payload: Payload, collection: string) =>
  (payload.collections?.[collection as never]?.config?.auth as { useSessions?: unknown } | undefined)?.useSessions === true

/** The masquerader's id if the request carries a genuine borrowed session's token. */
export const borrowedBy = (payload: Payload, headers: Headers | null | undefined) => borrowedClaim(payload, headers)?.by ?? null

/**
 * Whether the request is masquerading: it carries the signed state cookie, or a
 * borrowed session's token (so dropping the state cookie doesn't lift read-only).
 */
export const isMasquerading = (payload: Payload, headers: Headers | null | undefined) =>
  Boolean(masqStateOf(payload, headers) || borrowedBy(payload, headers))

/** The masquerader's id for a request, for audit trails: `masqueraderOf(req)`. */
export const masqueraderOf = (req: Pick<PayloadRequest, 'headers' | 'payload'>) => masqStateOf(req.payload, req.headers)?.by ?? null

export const masqOptions = (payload: Payload) => payload.config.custom?.masq as ResolvedMasqOptions

export function cookie(payload: Payload, slug: string, name: string, value: string, seconds: number, path = '/') {
  const auth = payload.collections[slug as never]!.config.auth
  return generateCookie<string>({
    name,
    value,
    path,
    httpOnly: true,
    secure: auth.cookies.secure,
    sameSite: 'Lax',
    domain: auth.cookies.domain ?? undefined,
    expires: new Date(Date.now() + seconds * 1000),
    returnCookieAsObject: false,
  })
}

/**
 * For your own server actions and route handlers that write through the Local
 * API without the request: refuse while masquerading (read-only masquerade).
 */
export function assertNotMasquerading(payload: Payload, headers: Headers | null | undefined) {
  if ((payload.config.custom?.masq as ResolvedMasqOptions | undefined)?.readOnly !== false && isMasquerading(payload, headers))
    throw new Error('Masquerade is read-only: nothing can be created, changed or deleted while masquerading.')
}
