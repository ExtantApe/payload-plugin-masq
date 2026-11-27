import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getPayload, handleEndpoints, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { masqPlugin, STATE_COOKIE, type MasqRecheckArgs, type MasqStopArgs } from '../src/index.js'

// A borrowed session is rechecked on every request: once the masquerader may no longer
// masquerade as the target, the session ends, whether the token comes in a cookie or a header.

const USERS = 'users'
type U = { id: string; email: string; role: string }
const PW = 'correct-horse-battery'
let config: Promise<SanitizedConfig>
let payload: Payload
let mongo: MongoMemoryReplSet
const stops: MasqStopArgs[] = []
let recheck: ((a: MasqRecheckArgs) => unknown) | undefined
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

const make = (role: string) =>
  payload.create({ collection: 'users', data: { email: `recheck-${role}-${++n}@example.com`, password: PW, role } as never }) as unknown as Promise<U>

async function masquerade(by: U, as: U): Promise<Jar> {
  const login = await rest('POST', `/${USERS}/login`, {}, { email: by.email, password: PW })
  expect(login.status).toBe(200)
  const res = await rest('POST', `/${USERS}/${as.id}/masq`, cookies({ 'payload-token': jarOf(login)['payload-token']! }), {})
  expect(res.status).toBe(200)
  const set = jarOf(res)
  return { 'payload-token': set['payload-token']!, [STATE_COOKIE]: set[STATE_COOKIE]! }
}

const me = async (headers: Record<string, string>) => ((await (await rest('GET', `/${USERS}/me`, headers)).json()) as { user: { id: string } | null }).user
const sessionsOf = async (u: U) => ((await payload.findByID({ collection: 'users', id: u.id, showHiddenFields: true })) as unknown as { sessions?: unknown[] }).sessions ?? []
const setRole = (u: U, role: string) => payload.update({ collection: 'users', id: u.id, data: { role } as never, context: { masqInternal: true } })

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  config = buildConfig({
    secret: 'recheck-test-secret-not-for-production',
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('masq-recheck'), ensureIndexes: true }),
    collections: [
      {
        slug: 'users',
        auth: { useSessions: true },
        access: { read: () => true, update: () => true },
        fields: [{ name: 'role', type: 'select', options: ['admin', 'member', 'staff'], defaultValue: 'member' }],
      },
    ],
    plugins: [
      masqPlugin({
        // Admins may masquerade as anyone but another admin.
        canMasquerade: ({ user, target }) => user.role === 'admin' && target?.role !== 'admin',
        recheck: (a) => (recheck ? recheck(a) : true),
        onStop: (a) => void stops.push(a),
      }),
    ],
  })
  payload = await getPayload({ config })
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

beforeEach(() => {
  recheck = undefined
  stops.length = 0
})

describe('a borrowed session ends once the masquerader may no longer masquerade', () => {
  it('keeps working while the rule still says yes (control)', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    expect((await me(bearer(jar['payload-token']!)))?.id).toBe(member.id)
    expect((await me(cookies(jar)))?.id).toBe(member.id)
    expect(stops).toEqual([])
  })

  it('a bearer token with no cookie stops working after the masquerader is demoted', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    expect((await me(bearer(token)))?.id).toBe(member.id)
    await setRole(admin, 'member')
    expect(await me(bearer(token))).toBeNull()
    expect((await payload.auth({ headers: new Headers(bearer(token)) })).user).toBeNull()
    expect(await sessionsOf(member)).toEqual([])
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: false, revoked: true })])
  })

  it('the cookie stops working after the masquerader is demoted', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    await setRole(admin, 'member')
    expect(await me(cookies(jar))).toBeNull()
    expect(stops).toHaveLength(1)
  })

  it('ends when the target changes so the rule says no', async () => {
    const [admin, staff] = [await make('admin'), await make('staff')]
    const token = (await masquerade(admin, staff))['payload-token']!
    await setRole(staff, 'admin')
    expect(await me(bearer(token))).toBeNull()
    expect(stops).toEqual([expect.objectContaining({ targetId: staff.id, revoked: true })])
  })

  it('ends when the masquerader account is deleted', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    await payload.delete({ collection: 'users', id: admin.id, context: { masqInternal: true } })
    expect(await me(bearer(token))).toBeNull()
  })

  it('a demoted masquerader is not restored by stop, and onStop is called once', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    await setRole(admin, 'member')
    const res = await rest('POST', `/${USERS}/masq/stop`, cookies(jar))
    expect(await res.json()).toMatchObject({ restored: false })
    expect(stops).toHaveLength(1)
    expect(await sessionsOf(member)).toEqual([])
  })
})

describe('the recheck option', () => {
  it('passes the masquerader and the target, and true keeps the session', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    const seen: string[] = []
    recheck = ({ masquerader, target }) => (seen.push(`${masquerader.id}>${target.id}`), true)
    expect((await me(bearer(token)))?.id).toBe(member.id)
    expect(seen).toContain(`${admin.id}>${member.id}`)
  })

  for (const [name, answer] of [
    ['false', () => false],
    ['a truthy value that is not true', () => 'yes'],
    ['a resolved 1', async () => 1],
    ['a throw', () => {
      throw new Error('deny list down')
    }],
  ] as const) {
    it(`ends the session on ${name}`, async () => {
      const [admin, member] = [await make('admin'), await make('member')]
      const token = (await masquerade(admin, member))['payload-token']!
      recheck = answer
      expect(await me(bearer(token))).toBeNull()
      expect(await sessionsOf(member)).toEqual([])
      expect(stops).toEqual([expect.objectContaining({ revoked: true })])
    })
  }

  it("leaves people's own sign-ins alone", async () => {
    const member = await make('member')
    const login = await rest('POST', `/${USERS}/login`, {}, { email: member.email, password: PW })
    recheck = () => false
    expect((await me(cookies({ 'payload-token': jarOf(login)['payload-token']! })))?.id).toBe(member.id)
    expect(stops).toEqual([])
  })
})

describe('fails closed', () => {
  it('runs signed out when deleting the borrowed session fails', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    await setRole(admin, 'member')
    const real = payload.db.updateOne
    payload.db.updateOne = (async () => {
      throw new Error('database down')
    }) as typeof real
    try {
      expect(await me(bearer(jar['payload-token']!))).toBeNull()
      expect(await me(cookies(jar))).toBeNull()
    } finally {
      payload.db.updateOne = real
    }
    expect(stops).toEqual([])
  })

  it('runs signed out when reading the masquerader fails', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const jar = await masquerade(admin, member)
    const real = payload.findByID
    payload.findByID = ((a: { id: string }) => {
      if (String(a.id) === admin.id) throw new Error('afterRead hook failed')
      return real.call(payload, a as never)
    }) as typeof real
    try {
      expect(await me(bearer(jar['payload-token']!))).toBeNull()
      expect(await me(cookies(jar))).toBeNull()
    } finally {
      payload.findByID = real
    }
    // Once reads work again, the still-allowed session works again.
    expect((await me(bearer(jar['payload-token']!)))?.id).toBe(member.id)
  })

  it("keeps the target's own sign-in made while the recheck was running", async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    let open!: () => void
    const gate = new Promise<void>((r) => (open = r))
    let entered!: () => void
    const inside = new Promise<void>((r) => (entered = r))
    recheck = async () => {
      entered()
      await gate
      return false
    }
    const pending = me(bearer(token))
    await inside
    recheck = undefined
    const login = await rest('POST', `/${USERS}/login`, {}, { email: member.email, password: PW })
    const own = jarOf(login)['payload-token']!
    open()
    expect(await pending).toBeNull()
    expect((await me(bearer(own)))?.id).toBe(member.id)
    expect(await sessionsOf(member)).toHaveLength(1)
  })

  it('reports onStop once when several requests revoke the same session at once', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    await setRole(admin, 'member')
    const users = await Promise.all([1, 2, 3, 4].map(() => me(bearer(token))))
    expect(users).toEqual([null, null, null, null])
    expect(stops).toHaveLength(1)
    expect(await sessionsOf(member)).toEqual([])
  })

  it('leaves the session for the stop endpoint when the path has a trailing slash', async () => {
    const [admin, member] = [await make('admin'), await make('member')]
    const token = (await masquerade(admin, member))['payload-token']!
    await setRole(admin, 'member')
    const strategy = (payload.collections.users!.config.auth.strategies ?? []).find((s) => s.name === 'masq-recheck')!
    const headers = new Headers(bearer(token))
    await strategy.authenticate({ headers, payload, req: { url: `http://localhost:3000/api/${USERS}/masq/stop/`, method: 'POST' } } as never)
    expect(await sessionsOf(member)).toHaveLength(1)
    expect(stops).toEqual([])
  })
})

describe('config', () => {
  it('refuses a collection that is not an auth collection', async () => {
    await expect(
      buildConfig({
        secret: 'x',
        telemetry: false,
        db: mongooseAdapter({ url: 'mongodb://127.0.0.1:1/never' }),
        collections: [{ slug: 'people', fields: [] }],
        plugins: [masqPlugin({ collection: 'people', canMasquerade: () => true })],
      }),
    ).rejects.toThrow(/not an auth collection/)
  })
})

// Payload's JWT strategy (and jose under it) accepts a token spelled more loosely than a plain read of it would:
// padding or whitespace in the signature, spaces around the cookie name, a percent-encoded value. Each spelling
// must still be seen as borrowed, or the recheck and read-only mode would let it through.
describe('other spellings of a borrowed token', () => {
  const spellings: [string, (t: string) => Record<string, string>][] = [
    ['JWT scheme with = padding', (t) => ({ Authorization: `JWT ${t}=` })],
    ['Bearer with a space inside the signature', (t) => ({ Authorization: `Bearer ${t.slice(0, -10)} ${t.slice(-10)}` })],
    ['cookie value with a trailing space', (t) => ({ cookie: `payload-token=${t} ;` })],
    ['cookie name followed by a space', (t) => ({ cookie: `payload-token =${t}` })],
    ['cookie name after a tab', (t) => ({ cookie: `x=1;\tpayload-token=${t}` })],
    ['percent-encoded cookie value', (t) => ({ cookie: `payload-token=%${t.charCodeAt(0).toString(16)}${t.slice(1)}` })],
  ]
  for (const [name, spell] of spellings) {
    it(`ends after the masquerader is demoted: ${name}`, async () => {
      const [admin, member] = [await make('admin'), await make('member')]
      const token = (await masquerade(admin, member))['payload-token']!
      expect((await me(spell(token)))?.id).toBe(member.id)
      await setRole(admin, 'member')
      expect(await me(spell(token))).toBeNull()
      expect(stops).toHaveLength(1)
    })
    it(`stays read-only: ${name}`, async () => {
      const [admin, member] = [await make('admin'), await make('member')]
      const token = (await masquerade(admin, member))['payload-token']!
      const res = await rest('PATCH', `/${USERS}/${member.id}`, spell(token), { role: 'staff' })
      expect(res.status).toBe(403)
      expect(((await payload.findByID({ collection: 'users', id: member.id })) as unknown as U).role).toBe('member')
    })
  }
})
