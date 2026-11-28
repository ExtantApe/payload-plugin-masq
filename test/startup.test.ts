import { mongooseAdapter } from '@payloadcms/db-mongodb'
import type { MongoMemoryReplSet } from 'mongodb-memory-server'
import { BasePayload, buildConfig, type CollectionBeforeOperationHook, createLocalReq, getPayload, handleEndpoints, type Config, type Payload, type PayloadRequest, type Plugin, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { masqPlugin, STATE_COOKIE, type ResolvedMasqOptions } from '../src/index.js'
import { READ_ONLY_MESSAGE } from '../src/plugin.js'
import { startMongo } from './mongo.js'

// Read-only masquerade on Payload as it is finally built: collections and globals that later plugins add or
// rebuild, the ones Payload adds itself, and jobs. Real Payload on in-memory MongoDB, through its REST router.

type U = { id: string; email: string; role: string }
type Jar = Record<string, string>
const PW = 'correct-horse-battery'
let config: Promise<SanitizedConfig>
let payload: Payload
let mongo: MongoMemoryReplSet
let admin: U
let member: U
const ran: string[] = []

const cookieHeader = (jar: Jar) =>
  Object.entries(jar)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
const jarOf = (res: Response) =>
  Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]!.split('=')).map(([k, ...v]) => [k!, v.join('=')]))

const AUTH = 'users' // the login collection's slug, as used in its routes

function rest(method: string, path: string, jar: Jar, body?: unknown) {
  const headers = new Headers({ cookie: cookieHeader(jar) })
  if (body !== undefined) headers.set('Content-Type', 'application/json')
  const request = new Request(`http://localhost:3000/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  return handleEndpoints({ config, request })
}

async function signIn(u: U): Promise<Jar> {
  const res = await rest('POST', `/${AUTH}/login`, {}, { email: u.email, password: PW })
  expect(res.status).toBe(200)
  return { 'payload-token': jarOf(res)['payload-token']! }
}

async function masquerade(as: U): Promise<Jar> {
  const res = await rest('POST', `/${AUTH}/${as.id}/masq`, await signIn(admin), {})
  expect(res.status).toBe(200)
  const set = jarOf(res)
  return { 'payload-token': set['payload-token']!, [STATE_COOKIE]: set[STATE_COOKIE]! }
}

const open = { create: () => true, read: () => true, update: () => true, delete: () => true }
const readOnly = async (res: Response) => {
  expect(res.status).toBe(403)
  expect(((await res.json()) as { errors: { message: string }[] }).errors[0]!.message).toBe(READ_ONLY_MESSAGE)
}

/** A plugin listed after Masq: it adds a collection and a global, and rebuilds the hooks of two collections. */
const laterPlugin: Plugin = (c: Config): Config => ({
  ...c,
  collections: [
    ...(c.collections ?? []).map((col) => (col.slug === 'rebuilt' || col.slug === 'users' ? { ...col, hooks: { ...col.hooks, beforeOperation: [(({ args }) => args) as CollectionBeforeOperationHook] } } : col)),
    { slug: 'late-notes', access: open, fields: [{ name: 'text', type: 'text' }] },
  ],
  globals: [...(c.globals ?? []), { slug: 'late-settings', access: { read: () => true, update: () => true }, fields: [{ name: 'motto', type: 'text' }] }],
})

const baseConfig = (url: string, plugins: Plugin[]) =>
  buildConfig({
    secret: 'startup-test-secret-not-for-production',
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url, ensureIndexes: true }),
    collections: [
      { slug: 'users', auth: true, access: { read: () => true }, fields: [{ name: 'role', type: 'text' }] },
      { slug: 'notes', folders: true, enableQueryPresets: true, access: open, fields: [{ name: 'text', type: 'text' }] },
      { slug: 'rebuilt', access: open, fields: [{ name: 'text', type: 'text' }] },
    ],
    globals: [{ slug: 'settings', access: { read: () => true, update: () => true }, fields: [{ name: 'motto', type: 'text' }] }],
    jobs: {
      tasks: [{ slug: 'record', handler: async ({ input }: { input: { label: string } }) => (ran.push(input.label), { output: {} }) }] as never,
      // Any signed-in user may queue and run jobs here, so the refusals below come from masquerade alone.
      access: { queue: ({ req }) => Boolean(req.user), run: ({ req }) => Boolean(req.user), cancel: ({ req }) => Boolean(req.user) },
    },
    plugins,
  })

const count = async (collection: string) => (await payload.count({ collection: collection as never })).totalDocs

beforeAll(async () => {
  mongo = await startMongo()
  config = baseConfig(mongo.getUri('masq-startup'), [masqPlugin({ canMasquerade: ({ user }) => user.role === 'admin' }), laterPlugin])
  payload = await getPayload({ config })
  admin = (await payload.create({ collection: 'users', data: { email: 'startup-admin@example.com', password: PW, role: 'admin' } as never })) as unknown as U
  member = (await payload.create({ collection: 'users', data: { email: 'startup-member@example.com', password: PW, role: 'member' } as never })) as unknown as U
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

describe('read-only masquerade on everything Payload built', () => {
  it('records at start-up that read-only masquerade is in place', () => {
    expect((payload.config.custom.masq as ResolvedMasqOptions).guarded).toBe(true)
  })

  it('refuses writes to a collection and a global that a later plugin added, and to a collection whose hooks it rebuilt', async () => {
    const jar = await masquerade(member)
    const before = [await count('late-notes'), await count('rebuilt')]
    await readOnly(await rest('POST', '/late-notes', jar, { text: 'x' }))
    await readOnly(await rest('POST', '/rebuilt', jar, { text: 'x' }))
    await readOnly(await rest('POST', '/globals/late-settings', jar, { motto: 'x' }))
    expect([await count('late-notes'), await count('rebuilt')]).toEqual(before)
    expect(((await payload.findGlobal({ slug: 'late-settings' as never })) as { motto?: string }).motto ?? null).toBeNull()
    // Reading is still fine.
    expect((await rest('GET', '/late-notes', jar)).status).toBe(200)
    expect((await rest('GET', '/globals/late-settings', jar)).status).toBe(200)
  })

  it('refuses writes to folders and query presets, which Payload adds itself', async () => {
    const jar = await masquerade(member)
    await readOnly(await rest('POST', '/payload-folders', jar, { name: 'masq folder', folderType: ['notes'] }))
    await readOnly(
      await rest('POST', '/payload-query-presets', jar, {
        title: 'masq preset',
        relatedCollection: 'notes',
        where: {},
        access: { read: { constraint: 'onlyMe' }, update: { constraint: 'onlyMe' }, delete: { constraint: 'onlyMe' } },
      }),
    )
    expect(await count('payload-folders')).toBe(0)
    expect(await count('payload-query-presets')).toBe(0)
  })

  it('still lets a borrowed session leave preferences and document locks, as documented', async () => {
    const jar = await masquerade(member)
    expect((await rest('POST', '/payload-preferences/masq-startup', jar, { value: { open: true } })).status).toBe(200)
  })

  it('refuses refreshing a borrowed session after a later plugin rebuilt the auth collection hooks', async () => {
    const jar = await masquerade(member)
    expect((await rest('POST', `/${AUTH}/refresh-token`, jar, {})).status).toBe(403)
    // A person's own session still refreshes.
    expect((await rest('POST', `/${AUTH}/refresh-token`, await signIn(member), {})).status).toBe(200)
  })

  it('refuses running jobs while masquerading and leaves the queued job alone', async () => {
    const job = (await payload.jobs.queue({ task: 'record' as never, input: { label: 'queued-before-masquerade' } as never })) as { id: string }
    const jar = await masquerade(member)
    await readOnly(await rest('GET', '/payload-jobs/run', jar))
    await readOnly(await rest('GET', '/payload-jobs/handle-schedules', jar))
    expect(ran).not.toContain('queued-before-masquerade')
    const still = (await payload.findByID({ collection: 'payload-jobs' as never, id: job.id })) as { processing?: boolean; completedAt?: string | null }
    expect(still.completedAt ?? null).toBeNull()
    expect(still.processing).toBe(false)
    await payload.delete({ collection: 'payload-jobs' as never, id: job.id })
  })

  it('refuses the jobs Local API with a masquerading request', async () => {
    const job = (await payload.jobs.queue({ task: 'record' as never, input: { label: 'queued-for-local-api' } as never })) as { id: string }
    const jar = await masquerade(member)
    const req = await createLocalReq({}, payload)
    ;(req as { headers: Headers }).headers = new Headers({ cookie: cookieHeader(jar) })
    const before = await count('payload-jobs')
    const input = { label: 'x' } as never
    await expect(payload.jobs.queue({ task: 'record' as never, input, req })).rejects.toThrow(READ_ONLY_MESSAGE)
    await expect(payload.jobs.queue({ task: 'record' as never, input, req, overrideAccess: false })).rejects.toThrow(READ_ONLY_MESSAGE)
    await expect(payload.jobs.run({ req })).rejects.toThrow(READ_ONLY_MESSAGE)
    await expect(payload.jobs.runByID({ id: job.id, req })).rejects.toThrow(READ_ONLY_MESSAGE)
    await expect(payload.jobs.cancelByID({ id: job.id, req })).rejects.toThrow(READ_ONLY_MESSAGE)
    await expect(payload.jobs.cancel({ where: { id: { equals: job.id } }, req })).rejects.toThrow(READ_ONLY_MESSAGE)
    expect(await count('payload-jobs')).toBe(before)
    expect(ran).not.toContain('queued-for-local-api')
    const still = (await payload.findByID({ collection: 'payload-jobs' as never, id: job.id })) as { completedAt?: string | null; hasError?: boolean }
    expect(still.completedAt ?? null).toBeNull()
    expect(still.hasError ?? false).toBe(false)
    await payload.delete({ collection: 'payload-jobs' as never, id: job.id })
  })

  it('refuses creating jobs while masquerading', async () => {
    const jar = await masquerade(member)
    const before = await count('payload-jobs')
    await readOnly(await rest('POST', '/payload-jobs', jar, { taskSlug: 'record', input: { label: 'x' } }))
    expect(await count('payload-jobs')).toBe(before)
  })
})

describe('people who are not masquerading, and Payload itself', () => {
  it('can write to collections and globals that later plugins and Payload added', async () => {
    const jar = await signIn(member)
    expect((await rest('POST', '/late-notes', jar, { text: 'mine' })).status).toBe(201)
    expect((await rest('POST', '/rebuilt', jar, { text: 'mine' })).status).toBe(201)
    expect((await rest('POST', '/globals/late-settings', jar, { motto: 'mine' })).status).toBe(200)
    expect((await rest('POST', '/payload-folders', jar, { name: 'my folder', folderType: ['notes'] })).status).toBe(201)
    await payload.updateGlobal({ slug: 'late-settings' as never, data: { motto: null } as never })
  })

  it('can run jobs over REST, and Payload runs queued jobs without a request', async () => {
    await payload.jobs.queue({ task: 'record' as never, input: { label: 'run-by-member' } as never })
    expect((await rest('GET', '/payload-jobs/run', await signIn(member))).status).toBe(200)
    expect(ran).toContain('run-by-member')
    await payload.jobs.queue({ task: 'record' as never, input: { label: 'run-by-payload' } as never })
    await payload.jobs.run()
    expect(ran).toContain('run-by-payload')
  })

  it('can queue jobs through the Local API with access checked', async () => {
    const req = await createLocalReq({ user: admin as never }, payload)
    const job = (await payload.jobs.queue({ task: 'record' as never, input: { label: 'queued' } as never, req, overrideAccess: false })) as { id: string }
    expect(job.id).toBeTruthy()
    await payload.delete({ collection: 'payload-jobs' as never, id: job.id })
  })

  it('runs migrations that write through the Local API', async () => {
    await payload.db.migrate({
      migrations: [
        {
          name: '20261128_masq_startup',
          up: async (args: unknown) => {
            const { payload: p, req } = args as { payload: Payload; req: PayloadRequest }
            await p.create({ collection: 'late-notes' as never, data: { text: 'from a migration' } as never, req })
          },
          down: async () => undefined,
        },
      ],
    })
    expect((await payload.find({ collection: 'late-notes' as never, where: { text: { equals: 'from a migration' } } })).totalDocs).toBe(1)
    expect((await payload.find({ collection: 'payload-migrations' as never, where: { name: { equals: '20261128_masq_startup' } } })).totalDocs).toBe(1)
  })
})

describe('when read-only masquerade cannot be confirmed', () => {
  it('start answers 503 and hands out no session, and returns to normal once it can be', async () => {
    const own = await signIn(admin)
    const sessions = async () => (((await payload.findByID({ collection: 'users', id: member.id, showHiddenFields: true })) as { sessions?: unknown[] }).sessions ?? []).length
    const before = await sessions()
    const saved = payload.authStrategies
    payload.authStrategies = saved.filter((s) => s.name !== 'masq-recheck')
    try {
      const res = await rest('POST', `/${AUTH}/${member.id}/masq`, own, {})
      expect(res.status).toBe(503)
      expect(res.headers.getSetCookie()).toEqual([])
      expect(await sessions()).toBe(before)
    } finally {
      payload.authStrategies = saved
    }
    expect((await rest('POST', `/${AUTH}/${member.id}/masq`, own, {})).status).toBe(200)
  })

  it('start answers 503 when a collection refuses the guard, and a running borrowed session signs in as nobody', async () => {
    const jar = await masquerade(member)
    const late = payload.collections['late-notes' as never]!.config as { hooks: Record<string, unknown> }
    const saved = late.hooks
    late.hooks = Object.freeze({ ...saved, beforeOperation: Object.freeze([]) })
    try {
      expect((await rest('POST', `/${AUTH}/${member.id}/masq`, await signIn(admin), {})).status).toBe(503)
      expect((payload.config.custom.masq as ResolvedMasqOptions).guarded).toBe(false)
      const me = (await (await rest('GET', `/${AUTH}/me`, jar)).json()) as { user: unknown }
      expect(me.user).toBeNull()
    } finally {
      late.hooks = saved
    }
    const me = (await (await rest('GET', `/${AUTH}/me`, jar)).json()) as { user: { id: string } | null }
    expect(me.user?.id).toBe(member.id)
  })

  it('Payload refuses to start', async () => {
    // A later plugin that drops the masquerade sign-in check from the auth collection.
    const dropCheck: Plugin = (c) => ({
      ...c,
      collections: (c.collections ?? []).map((col) => (col.slug === 'users' ? { ...col, auth: { ...(col.auth as object), strategies: [] } } : col)),
    })
    const refused = baseConfig(mongo.getUri('masq-startup-refused'), [masqPlugin({ canMasquerade: () => true }), dropCheck])
    const other = new BasePayload()
    try {
      await expect(other.init({ config: refused })).rejects.toThrow(/read-only masquerade could not be put in place/)
    } finally {
      await other.destroy()
    }
  })
})
