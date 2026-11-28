import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getPayload, handleEndpoints, type Payload, type SanitizedConfig } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { decodeState, masqPlugin, STATE_COOKIE, type MasqStartArgs, type MasqStopArgs } from '../src/index.js'

// Number ids, where the database reads "01" and "1.0" as 1. Real Payload on in-memory MongoDB with a number
// `id` field; the SQL adapters, whose default ids are numbers, aren't run here.

type U = { id: number; email: string; role: string }
const PW = 'correct-horse-battery'
let config: Promise<SanitizedConfig>
let payload: Payload
let mongo: MongoMemoryReplSet
const admin: U = { id: 1, email: 'num-admin@example.com', role: 'admin' }
const member: U = { id: 2, email: 'num-member@example.com', role: 'member' }
const started: MasqStartArgs[] = []
const stops: MasqStopArgs[] = []
/** The id of a user whose read hook hands back the document with this id instead. */
let rewrite: { of: number; to: unknown } | null = null

type Jar = Record<string, string>
const jarOf = (res: Response) =>
  Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]!.split('=')).map(([k, ...v]) => [k!, v.join('=')]))
function rest(method: string, path: string, jar: Jar, body?: unknown) {
  const request = new Request(`http://localhost:3000/api${path}`, {
    method,
    headers: { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '), 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return handleEndpoints({ config, request })
}
async function signIn(u: U): Promise<Jar> {
  const res = await rest('POST', '/users/login', {}, { email: u.email, password: PW })
  expect(res.status).toBe(200)
  return { 'payload-token': jarOf(res)['payload-token']! }
}
const errorOf = async (res: Response) => ((await res.json()) as { errors?: { message: string }[] }).errors?.[0]?.message
const signsInAs = async (token: string) => (await payload.auth({ headers: new Headers({ Authorization: `Bearer ${token}` }) })).user?.id ?? null

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  config = buildConfig({
    secret: 'numeric-test-secret-not-for-production',
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('masq-numeric'), ensureIndexes: true }),
    collections: [
      {
        slug: 'users',
        auth: true,
        access: { read: () => true },
        hooks: { afterRead: [({ doc }) => (rewrite && doc.id === rewrite.of ? { ...doc, id: rewrite.to } : doc)] },
        fields: [{ name: 'id', type: 'number', required: true }, { name: 'role', type: 'select', options: ['admin', 'member'], defaultValue: 'member' }],
      },
    ],
    plugins: [masqPlugin({ canMasquerade: ({ user }) => user.role === 'admin', onStart: (a) => void started.push(a), onStop: (a) => void stops.push(a) })],
  })
  payload = await getPayload({ config })
  for (const u of [admin, member]) await payload.create({ collection: 'users', data: { ...u, password: PW } as never })
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

describe('number ids', () => {
  it.each(['1', '01', '1.0', '001'])('refuses yourself spelled %s', async (id) => {
    const before = started.length
    const res = await rest('POST', `/users/${id}/masq`, await signIn(admin), {})
    expect(res.status).toBe(400)
    expect(await errorOf(res)).toBe('Choose another user.')
    expect(res.headers.getSetCookie()).toEqual([])
    expect(started.length).toBe(before)
  })

  it.each(['2', '02', '2.0'])('records the found id for a target spelled %s, and Return ends the borrowed session', async (id) => {
    const res = await rest('POST', `/users/${id}/masq`, await signIn(admin), {})
    expect(res.status).toBe(200)
    expect(started.at(-1)!.target.id).toBe(2)
    const set = jarOf(res)
    expect(decodeState(payload.secret, set[STATE_COOKIE])).toMatchObject({ by: '1', as: '2' })
    const borrowed = set['payload-token']!
    expect(await signsInAs(borrowed)).toBe(2)
    const before = stops.length
    const back = await rest('POST', '/users/masq/stop', set)
    expect(await back.json()).toMatchObject({ restored: true, redirect: '/admin/collections/users/2' })
    expect(stops.slice(before)).toEqual([expect.objectContaining({ masqueraderId: '1', targetId: '2', expired: false, restored: true })])
    expect(await signsInAs(borrowed)).toBeNull()
  })

  it('gives someone who is not allowed one answer for real, made-up and odd spellings', async () => {
    const jar = await signIn(member)
    const got = []
    for (const id of ['1', '01', '1.0', '999', '0999', '999.0', 'abc', '1e0', '-1', 'NaN']) {
      const res = await rest('POST', `/users/${id}/masq`, jar, {})
      got.push({ status: res.status, body: await res.text(), headers: [...res.headers] })
    }
    for (const a of got) expect(a).toEqual(got[0])
    expect(got[0]!.status).toBe(403)
  })

  it.each([
    ['no id', undefined],
    ['an empty id', ''],
    ['an object for an id', {}],
    ['a number that is not finite', Number.NaN],
  ])('starts nothing when the lookup hands back %s', async (_name, to) => {
    const own = await signIn(admin)
    const before = started.length
    rewrite = { of: 2, to }
    try {
      const res = await rest('POST', '/users/2/masq', own, {})
      expect(res.status).toBe(404)
      expect(await errorOf(res)).toBe('User not found.')
      expect(res.headers.getSetCookie()).toEqual([])
      expect(started.length).toBe(before)
    } finally {
      rewrite = null
    }
  })
})
