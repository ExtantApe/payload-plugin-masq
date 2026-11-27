import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getPayload, handleEndpoints, type Endpoint, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { decodeState, masqPlugin, STATE_COOKIE, type MasqState, type MasqStopArgs } from '../src/index.js'
import { encodeState } from '../src/state.js'

// The stop endpoint: it removes the borrowed session in a transaction, reports onStop once, fails closed when
// the delete can't be confirmed, and says `expired` only when the session had really ended already.

const USERS = 'users'
const RETURN = 'payload-masq-return'
type U = { id: string; email: string; role: string }
const PW = 'correct-horse-battery'
let config: Promise<SanitizedConfig>
let payload: Payload
let mongo: MongoMemoryReplSet
const stops: MasqStopArgs[] = []
let n = 0

type Jar = Record<string, string>
const jarOf = (res: Response) =>
  Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]!.split('=')).map(([k, ...v]) => [k!, v.join('=')]))

function rest(method: string, path: string, headers: Record<string, string>, body?: unknown) {
  const h = new Headers(headers)
  if (body !== undefined) h.set('Content-Type', 'application/json')
  return handleEndpoints({ config, request: new Request(`http://localhost:3000/api${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }) })
}
const cookies = (jar: Jar) => ({ cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') })
const bearer = (token: string) => ({ Authorization: `Bearer ${token}` })
const stop = (headers: Record<string, string>) => rest('POST', `/${USERS}/masq/stop`, headers)
type StopBody = { ok: boolean; restored: boolean; redirect: string }
const bodyOf = async (res: Response) => (await res.json()) as StopBody

const make = (role: string) =>
  payload.create({ collection: 'users', data: { email: `stop-${role}-${++n}@example.com`, password: PW, role } as never }) as unknown as Promise<U>

const signIn = async (u: U) => {
  const res = await rest('POST', `/${USERS}/login`, {}, { email: u.email, password: PW })
  expect(res.status).toBe(200)
  return jarOf(res)['payload-token']!
}

/** Starts a masquerade and returns all three cookies the browser holds afterwards, plus the masquerader's own token. */
async function masquerade(by: U, as: U): Promise<Jar & { own: string }> {
  const own = await signIn(by)
  const res = await rest('POST', `/${USERS}/${as.id}/masq`, cookies({ 'payload-token': own }), {})
  expect(res.status).toBe(200)
  const set = jarOf(res)
  return { 'payload-token': set['payload-token']!, [STATE_COOKIE]: set[STATE_COOKIE]!, [RETURN]: set[RETURN]!, own }
}
/** The cookies a browser would send, without the test's own bookkeeping. */
const browser = ({ own: _own, ...jar }: Jar) => jar
const without = (jar: Jar, ...names: string[]) => Object.fromEntries(Object.entries(browser(jar)).filter(([k]) => !names.includes(k)))

const me = async (headers: Record<string, string>) => ((await (await rest('GET', `/${USERS}/me`, headers)).json()) as { user: { id: string } | null }).user
const sessionsOf = async (u: U) => ((await payload.findByID({ collection: 'users', id: u.id, showHiddenFields: true })) as unknown as { sessions?: unknown[] }).sessions ?? []

/** The same state cookie as an older version issued it: signed, with no session id. */
function withoutSid(stateCookie: string): string {
  const { sid: _sid, ...old } = decodeState(payload.secret, stateCookie) as MasqState & { sid?: string }
  return encodeState(payload.secret, old as MasqState)
}

/**
 * Runs `fn` with the stop endpoint held until `count` requests have signed in and reached it, so they all saw
 * the borrowed session alive before any of them removes it.
 */
async function allSignedInFirst<T>(count: number, fn: () => Promise<T>): Promise<T> {
  const endpoint = ((await config).collections.find((c) => c.slug === USERS)!.endpoints as Endpoint[]).find((e) => e.path === '/masq/stop')!
  const real = endpoint.handler
  let arrived = 0
  let open!: () => void
  const gate = new Promise<void>((r) => (open = r))
  endpoint.handler = async (req) => {
    if (++arrived >= count) open()
    await gate
    return real(req)
  }
  try {
    return await fn()
  } finally {
    endpoint.handler = real
  }
}

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  config = buildConfig({
    secret: 'stop-test-secret-not-for-production',
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('masq-stop'), ensureIndexes: true }),
    collections: [
      {
        slug: 'users',
        auth: { useSessions: true },
        access: { read: () => true, update: () => true },
        fields: [{ name: 'role', type: 'select', options: ['admin', 'member'], defaultValue: 'member' }],
      },
    ],
    plugins: [masqPlugin({ canMasquerade: ({ user, target }) => user.role === 'admin' && target?.role !== 'admin', onStop: (a) => void stops.push(a) })],
  })
  payload = await getPayload({ config })
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

beforeEach(() => {
  stops.length = 0
})

describe('stop removes the borrowed session in a transaction', () => {
  it("keeps the target's own sign-in made while stop was running", async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    // Hold stop's write to the target's sessions until the target has signed in.
    const real = payload.db.updateOne
    let held = false
    let open!: () => void
    const gate = new Promise<void>((r) => (open = r))
    let entered!: () => void
    const inside = new Promise<void>((r) => (entered = r))
    payload.db.updateOne = (async (args: { collection: string; data: { sessions?: unknown } }) => {
      if (!held && args.collection === USERS && args.data?.sessions) {
        held = true
        entered()
        await gate
      }
      return real.call(payload.db, args as never)
    }) as typeof real
    let own: string
    let res: Response
    try {
      const pending = stop(cookies(browser(jar)))
      await inside
      own = await signIn(member)
      open()
      res = await pending
    } finally {
      open()
      payload.db.updateOne = real
    }
    expect(await bodyOf(res)).toMatchObject({ ok: true, restored: true })
    // The sign-in made meanwhile survives, and the borrowed session is gone.
    expect((await me(bearer(own)))?.id).toBe(member.id)
    expect(await me(bearer(jar['payload-token']!))).toBeNull()
    expect(await sessionsOf(member)).toHaveLength(1)
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
  })

  it('reports onStop once when several stops arrive at once', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    const responses = await allSignedInFirst(4, () => Promise.all([1, 2, 3, 4].map(() => stop(cookies(browser(jar))))))
    for (const res of responses) {
      expect(res.status).toBe(200)
      // The borrowed session is gone for every one of them, so each may hand the masquerader's own token back.
      expect(await bodyOf(res)).toMatchObject({ ok: true, restored: true })
      expect(jarOf(res)['payload-token']).toBe(jar.own)
    }
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
    expect(await sessionsOf(member)).toEqual([])
  })

  it('reports onStop once when several stops arrive at once without the state cookie', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    const responses = await allSignedInFirst(4, () => Promise.all([1, 2, 3, 4].map(() => stop(bearer(token)))))
    for (const res of responses) expect(await bodyOf(res)).toMatchObject({ ok: true, restored: false })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: false })])
    expect(await sessionsOf(member)).toEqual([])
  })
})

describe('stop fails closed when it cannot confirm the borrowed session is gone', () => {
  for (const [name, headersOf] of [
    ['with the state cookie', (jar: Jar) => cookies(browser(jar))],
    ['without the state cookie', (jar: Jar) => cookies(without(jar, STATE_COOKIE))],
    ['with the state cookie and no token', (jar: Jar) => cookies(without(jar, 'payload-token'))],
  ] as const) {
    it(`signs the browser out, claims no success and reports no stop: ${name}`, async () => {
      const [admin, member] = [await make('admin'), await make('member')]
      const jar = await masquerade(admin, member)
      const logged = vi.spyOn(payload.logger, 'error')
      const real = payload.db.updateOne
      payload.db.updateOne = (async () => {
        throw new Error('database down')
      }) as typeof real
      let res: Response
      try {
        res = await stop(headersOf(jar))
      } finally {
        payload.db.updateOne = real
      }
      expect(res.status).toBe(500)
      expect(await bodyOf(res)).toMatchObject({ ok: false, restored: false, redirect: '/admin/login' })
      // Every masquerade cookie is cleared, and the masquerader's own token is not handed back.
      const set = jarOf(res)
      expect(set['payload-token']).toBe('')
      expect(set[STATE_COOKIE]).toBe('')
      expect(set[RETURN]).toBe('')
      expect(stops).toEqual([])
      // It is said out loud: the session is still there, and the log says so.
      expect(await sessionsOf(member)).toHaveLength(1)
      expect(logged.mock.calls.some(([entry]) => /could not end a borrowed session/.test(String((entry as { msg?: string }).msg)))).toBe(true)
      logged.mockRestore()
    })
  }
})

describe("onStop's expired flag", () => {
  it('is false when the state cookie and the borrowed token match (control)', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    expect(await bodyOf(await stop(cookies(browser(jar))))).toMatchObject({ ok: true, restored: true })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
    expect(await sessionsOf(member)).toEqual([])
  })

  it("is false when the target's own token signs in beside the state cookie, and only the borrowed session ends", async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    const own = await signIn(member)
    await stop({ ...bearer(own), ...cookies(browser(jar)) })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false })])
    // The session the state cookie names is ended; the target's own is untouched.
    expect(await me(bearer(jar['payload-token']!))).toBeNull()
    expect((await me(bearer(own)))?.id).toBe(member.id)
    expect(await sessionsOf(member)).toHaveLength(1)
  })

  it("is false when another masquerader's borrowed token signs in beside the state cookie, and that other session is left alone", async () => {
    const [admin1, admin2, member] = [await make('admin'), await make('admin'), await make('member')]
    const jar1 = await masquerade(admin1, member)
    const token2 = (await masquerade(admin2, member))['payload-token']!
    await stop({ ...bearer(token2), ...cookies(browser(jar1)) })
    // One report, for the masquerade the state cookie names, which this stop ended.
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin1.id, targetId: member.id, expired: false })])
    expect(await me(bearer(jar1['payload-token']!))).toBeNull()
    expect((await me(bearer(token2)))?.id).toBe(member.id)
    expect(await sessionsOf(member)).toHaveLength(1)
  })

  it('is false when a borrowed token for another target signs in beside the state cookie, and that other session is left alone', async () => {
    const [admin, a, b] = [await make('admin'), await make('member'), await make('member')]
    const jarA = await masquerade(admin, a)
    const tokenB = (await masquerade(admin, b))['payload-token']!
    await stop({ ...bearer(tokenB), ...cookies(browser(jarA)) })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: a.id, expired: false })])
    expect(await sessionsOf(a)).toEqual([])
    expect((await me(bearer(tokenB)))?.id).toBe(b.id)
    expect(await sessionsOf(b)).toHaveLength(1)
  })

  it('is true when the session the state cookie names has ended, whatever other token signs in', async () => {
    const [admin1, admin2, member] = [await make('admin'), await make('admin'), await make('member')]
    const jar1 = await masquerade(admin1, member)
    const token2 = (await masquerade(admin2, member))['payload-token']!
    // End admin1's borrowed session first, by its own token.
    await stop(bearer(jar1['payload-token']!))
    stops.length = 0
    await stop({ ...bearer(token2), ...cookies(browser(jar1)) })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin1.id, targetId: member.id, expired: true })])
    expect((await me(bearer(token2)))?.id).toBe(member.id)
  })

  it('is false, with the masquerader from the claim, when there is no state cookie', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    expect(await bodyOf(await stop(cookies(without(jar, STATE_COOKIE))))).toMatchObject({ ok: true, restored: false })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: false })])
    expect(await sessionsOf(member)).toEqual([])
  })

  it('is true when the borrowed token has run out', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const opts = payload.config.custom!.masq as { duration: number }
    const before = opts.duration
    opts.duration = 1
    let jar: Jar & { own: string }
    try {
      jar = await masquerade(admin, member)
    } finally {
      opts.duration = before
    }
    await new Promise((r) => setTimeout(r, 2100))
    expect(await me(bearer(jar['payload-token']!))).toBeNull()
    expect(await bodyOf(await stop(cookies(browser(jar))))).toMatchObject({ ok: true, restored: true })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: true, restored: true })])
  })

  it('is false when the browser lost the borrowed token but the session is alive, and stop ends it', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    expect(await bodyOf(await stop(cookies(without(jar, 'payload-token'))))).toMatchObject({ ok: true, restored: true })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
    expect(await me(bearer(jar['payload-token']!))).toBeNull()
    expect(await sessionsOf(member)).toEqual([])
  })

  it('is true when the browser lost the borrowed token and the session is gone', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    await payload.db.updateOne({ collection: USERS, id: member.id, data: { sessions: [] }, returning: false })
    await stop(cookies(without(jar, 'payload-token')))
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: true, restored: true })])
  })
})

describe('a state cookie issued before it carried the session id', () => {
  it('still ends the borrowed session that signs in with the same masquerader and target', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    const res = await stop(cookies({ ...browser(jar), [STATE_COOKIE]: withoutSid(jar[STATE_COOKIE]!) }))
    expect(await bodyOf(res)).toMatchObject({ ok: true, restored: true })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
    expect(await sessionsOf(member)).toEqual([])
  })

  it('ends nothing and does not say expired when another token signs in', async () => {
    const [admin1, admin2, member] = [await make('admin'), await make('admin'), await make('member')]
    const jar1 = await masquerade(admin1, member)
    const token2 = (await masquerade(admin2, member))['payload-token']!
    await stop({ ...bearer(token2), ...cookies({ ...browser(jar1), [STATE_COOKIE]: withoutSid(jar1[STATE_COOKIE]!) }) })
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin1.id, targetId: member.id, expired: false })])
    expect(await sessionsOf(member)).toHaveLength(2)
    expect((await me(bearer(token2)))?.id).toBe(member.id)
  })
})
