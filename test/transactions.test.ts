import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryServer } from 'mongodb-memory-server'
import { BasePayload, buildConfig, getPayload, handleEndpoints, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { masqPlugin, STATE_COOKIE, type MasqPluginOptions, type MasqStopArgs } from '../src/index.js'

// Masq changes sessions only inside a transaction. These run against a standalone MongoDB, which has none.

const USERS = 'users'
const PW = 'correct-horse-battery'
let mongo: MongoMemoryServer
let n = 0
const live: Payload[] = []

type Jar = Record<string, string>
const jarOf = (res: Response) =>
  Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]!.split('=')).map(([k, ...v]) => [k!, v.join('=')]))
const cookies = (jar: Jar) => ({ cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') })

/** A config on the standalone server. `adapterTransactions: false` is how Payload is told a MongoDB has none. */
const configFor = (options: Partial<MasqPluginOptions>, adapterTransactions: boolean, stops: MasqStopArgs[] = []) =>
  buildConfig({
    secret: 'transactions-test-secret-not-for-production',
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri(`masq-tx-${++n}`), ...(adapterTransactions ? {} : { transactionOptions: false }) }),
    collections: [
      {
        slug: 'users',
        auth: { useSessions: true },
        fields: [{ name: 'role', type: 'select', options: ['admin', 'member'], defaultValue: 'member' }],
      },
    ],
    plugins: [masqPlugin({ canMasquerade: ({ user, target }) => user.role === 'admin' && target?.role !== 'admin', onStop: (a) => void stops.push(a), ...options })],
  })

/** Start-up on its own, for the cases where it must fail. */
async function boot(config: SanitizedConfig): Promise<void> {
  const p = new BasePayload()
  live.push(p)
  await p.init({ config })
}

/** A running site: its own cached instance, which the REST router then uses too. */
type Site = { config: SanitizedConfig; key: string; payload: Payload }
async function site(config: SanitizedConfig, disableOnInit = false): Promise<Site> {
  const key = `masq-tx-site-${++n}`
  const payload = await getPayload({ config, key, disableOnInit })
  live.push(payload)
  return { config, key, payload }
}

const rest = ({ config, key }: Site, method: string, path: string, headers: Record<string, string>, body?: unknown) => {
  const h = new Headers(headers)
  if (body !== undefined) h.set('Content-Type', 'application/json')
  return handleEndpoints({
    config,
    payloadInstanceCacheKey: key,
    request: new Request(`http://localhost:3000/api${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }),
  })
}

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
}, 120_000)

afterAll(async () => {
  for (const p of live) await p.destroy().catch(() => undefined)
  await mongo?.stop()
})

describe('a database without transactions', () => {
  it('stops start-up when the adapter hands out a transaction that cannot run', async () => {
    const config = await configFor({}, true)
    await expect(boot(config)).rejects.toThrow(/payload-plugin-masq: the database can't run transactions.*allowNoTransactions/s)
  })

  it('stops start-up when the adapter gives no transaction', async () => {
    const config = await configFor({}, false)
    await expect(boot(config)).rejects.toThrow(/payload-plugin-masq: the database can't run transactions \(the adapter gave no transaction\)/)
  })

  it('refuses an allowNoTransactions that is not true or false', () => {
    for (const allowNoTransactions of [0, 1, '', 'yes', null])
      expect(() => masqPlugin({ canMasquerade: () => true, allowNoTransactions: allowNoTransactions as never })({ collections: [{ slug: 'users', auth: true, fields: [] }] } as never)).toThrow(/allowNoTransactions/)
  })
})

type U = { id: string; email: string }
const make = (p: Payload, role: string) =>
  p.create({ collection: 'users', data: { email: `tx-${role}-${++n}@example.com`, password: PW, role } as never }) as unknown as Promise<U>
const sessionsOf = async (p: Payload, u: U) => ((await p.findByID({ collection: 'users', id: u.id, showHiddenFields: true })) as unknown as { sessions?: unknown[] }).sessions ?? []

describe('allowNoTransactions: true', () => {
  it('starts up, and a masquerade starts and stops without a transaction', async () => {
    const stops: MasqStopArgs[] = []
    const config = await configFor({ allowNoTransactions: true }, false, stops)
    const s = await site(config)
    const p = s.payload
    const [admin, member] = [await make(p, 'admin'), await make(p, 'member')]
    const login = await rest(s, 'POST', `/${USERS}/login`, {}, { email: admin.email, password: PW })
    const own = jarOf(login)['payload-token']!
    const started = await rest(s, 'POST', `/${USERS}/${member.id}/masq`, cookies({ 'payload-token': own }), {})
    expect(started.status).toBe(200)
    expect(await sessionsOf(p, member)).toHaveLength(1)
    const jar = jarOf(started)
    const stopped = await rest(s, 'POST', `/${USERS}/masq/stop`, cookies({ 'payload-token': jar['payload-token']!, [STATE_COOKIE]: jar[STATE_COOKIE]!, 'payload-masq-return': jar['payload-masq-return']! }))
    expect(stopped.status).toBe(200)
    expect(await stopped.json()).toMatchObject({ ok: true, restored: true })
    expect(await sessionsOf(p, member)).toEqual([])
    expect(stops).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
  })
})

describe('start-up checks skipped on a database without transactions', () => {
  it('start refuses and adds no session', async () => {
    const config = await configFor({}, false)
    const s = await site(config, true)
    const p = s.payload
    const [admin, member] = [await make(p, 'admin'), await make(p, 'member')]
    const login = await rest(s, 'POST', `/${USERS}/login`, {}, { email: admin.email, password: PW })
    const own = jarOf(login)['payload-token']!
    const started = await rest(s, 'POST', `/${USERS}/${member.id}/masq`, cookies({ 'payload-token': own }), {})
    expect(started.status).toBe(500)
    expect(jarOf(started)['payload-token']).toBeUndefined()
    expect(await sessionsOf(p, member)).toEqual([])
  })

  it('stop refuses to end a session without a transaction, signs the browser out and reports nothing', async () => {
    const stops: MasqStopArgs[] = []
    const config = await configFor({ allowNoTransactions: true }, false, stops)
    const s = await site(config, true)
    const p = s.payload
    const [admin, member] = [await make(p, 'admin'), await make(p, 'member')]
    const login = await rest(s, 'POST', `/${USERS}/login`, {}, { email: admin.email, password: PW })
    const started = await rest(s, 'POST', `/${USERS}/${member.id}/masq`, cookies({ 'payload-token': jarOf(login)['payload-token']! }), {})
    expect(started.status).toBe(200)
    const jar = jarOf(started)
    // The same site with the opt-out taken away again.
    const opts = p.config.custom!.masq as { allowNoTransactions: boolean }
    opts.allowNoTransactions = false
    const stopped = await rest(s, 'POST', `/${USERS}/masq/stop`, cookies({ 'payload-token': jar['payload-token']!, [STATE_COOKIE]: jar[STATE_COOKIE]!, 'payload-masq-return': jar['payload-masq-return']! }))
    expect(stopped.status).toBe(500)
    expect(await stopped.json()).toMatchObject({ ok: false, restored: false })
    expect(jarOf(stopped)['payload-token']).toBe('')
    expect(stops).toEqual([])
    expect(await sessionsOf(p, member)).toHaveLength(1)
  })
})
