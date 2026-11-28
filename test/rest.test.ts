import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { GRAPHQL_POST } from '@payloadcms/next/routes'
import type { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getFieldsToSign, getPayload, handleEndpoints, jwtSign, type Payload, type SanitizedConfig } from 'payload'
import { addSessionToUser } from 'payload/shared'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { decodeState, masqPlugin, STATE_COOKIE, type MasqStopArgs } from '../src/index.js'
import { READ_ONLY_MESSAGE } from '../src/plugin.js'
import { encodeState } from '../src/state.js'
import { startMongo } from './mongo.js'

// Read-only masquerade through real HTTP requests: Payload's own REST router
// (`handleEndpoints`, what `@payloadcms/next/routes` serves) and its GraphQL route.

type U = { id: string; email: string; role: string }
const PW = 'correct-horse-battery'
let config: Promise<SanitizedConfig>
let payload: Payload
let mongo: MongoMemoryReplSet
let admin: U
let admin2: U
const stops: MasqStopArgs[] = []
let member: U
let noteId: string

type Jar = Record<string, string>
const cookieHeader = (jar: Jar) =>
  Object.entries(jar)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
const jarOf = (res: Response) =>
  Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]!.split('=')).map(([k, ...v]) => [k!, v.join('=')]))

/** A browser-like request to the REST API, signed in by the cookies in `jar`. */
function rest(method: string, path: string, jar: Jar, body?: unknown) {
  const headers = new Headers({ cookie: cookieHeader(jar) })
  if (body !== undefined) headers.set('Content-Type', 'application/json')
  const request = new Request(`http://localhost:3000/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  return handleEndpoints({ config, request })
}

/** A GraphQL request, signed in by the cookies in `jar`. */
async function gql(query: string, jar: Jar) {
  const request = new Request('http://localhost:3000/api/graphql', {
    method: 'POST',
    headers: { cookie: cookieHeader(jar), 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  })
  return (await (await GRAPHQL_POST(config)(request)).json()) as { data?: Record<string, unknown>; errors?: { message: string }[] }
}

async function signIn(u: U): Promise<Jar> {
  const res = await rest('POST', '/users/login', {}, { email: u.email, password: PW })
  expect(res.status).toBe(200)
  return { 'payload-token': jarOf(res)['payload-token']! }
}

/** Starts a masquerade over REST and returns the browser's cookies afterwards. */
async function masquerade(as: U): Promise<Jar> {
  const own = await signIn(admin)
  const res = await rest('POST', `/users/${as.id}/masq`, own, {})
  expect(res.status).toBe(200)
  const set = jarOf(res)
  return { 'payload-token': set['payload-token']!, [STATE_COOKIE]: set[STATE_COOKIE]! }
}

beforeAll(async () => {
  mongo = await startMongo()
  config = buildConfig({
    secret: 'rest-test-secret-not-for-production',
    // Refusals are expected here; keep their error logs out of the test output.
    logger: { options: { level: 'silent' } },
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('masq-rest'), ensureIndexes: true }),
    collections: [
      { slug: 'users', auth: true, access: { read: () => true, update: () => true, unlock: () => true }, fields: [{ name: 'role', type: 'select', options: ['admin', 'member'], defaultValue: 'member' }, { name: 'name', type: 'text' }] },
      { slug: 'notes', versions: true, access: { create: () => true, read: () => true, readVersions: () => true, update: () => true, delete: () => true }, fields: [{ name: 'text', type: 'text' }] },
    ],
    globals: [{ slug: 'settings', versions: true, access: { read: () => true, readVersions: () => true, update: () => true }, fields: [{ name: 'motto', type: 'text' }] }],
    plugins: [masqPlugin({ canMasquerade: ({ user }) => user.role === 'admin', onStop: (a) => void stops.push(a) })],
  })
  payload = await getPayload({ config })
  const make = (email: string, role: string, name: string) =>
    payload.create({ collection: 'users', data: { email, password: PW, role, name } as never }) as unknown as Promise<U>
  admin = await make('rest-admin@example.com', 'admin', 'Ada Admin')
  admin2 = await make('rest-admin2@example.com', 'admin', 'Bea Admin')
  member = await make('rest-member@example.com', 'member', 'Cy Member')
  noteId = String((await payload.create({ collection: 'notes', data: { text: 'original' } })).id)
  await payload.updateGlobal({ slug: 'settings', data: { motto: 'original' } })
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

/** Ids of the oldest version of the note and of the settings global (both say 'original'). */
async function originalVersions() {
  const note = (await payload.findVersions({ collection: 'notes', where: { parent: { equals: noteId } }, sort: 'createdAt', limit: 1 })).docs[0]!
  const global = (await payload.findGlobalVersions({ slug: 'settings', sort: 'createdAt', limit: 1 })).docs[0]!
  return { note: String(note.id), global: String(global.id) }
}

const errorOf = async (res: Response) => ((await res.json()) as { errors?: { message: string }[] }).errors?.[0]?.message

describe('read-only over REST', () => {
  it('lets the same requests write when nobody is masquerading (control)', async () => {
    const jar = await signIn(member)
    const created = await rest('POST', '/notes', jar, { text: 'control' })
    expect(created.status).toBe(201)
    const id = ((await created.json()) as { doc: { id: string } }).doc.id
    expect((await rest('PATCH', `/notes/${id}`, jar, { text: 'control 2' })).status).toBe(200)
    expect((await rest('DELETE', `/notes/${id}`, jar)).status).toBe(200)
    expect((await rest('POST', '/globals/settings', jar, { motto: 'original' })).status).toBe(200)
  })

  it('refuses creates, updates and deletes on collections and globals while masquerading', async () => {
    const jar = await masquerade(member)
    const tries = [
      rest('POST', '/notes', jar, { text: 'new' }),
      rest('PATCH', `/notes/${noteId}`, jar, { text: 'changed' }),
      rest('PATCH', `/notes?where[id][equals]=${noteId}`, jar, { text: 'changed in bulk' }),
      rest('DELETE', `/notes/${noteId}`, jar),
      rest('DELETE', `/notes?where[id][equals]=${noteId}`, jar),
      rest('PATCH', `/users/${member.id}`, jar, { name: 'Changed' }),
      rest('POST', '/globals/settings', jar, { motto: 'changed' }),
    ]
    for (const res of await Promise.all(tries)) {
      const message = await errorOf(res.clone())
      // Bulk operations report per-document errors with a 400; single ones a 403.
      expect([400, 403]).toContain(res.status)
      expect(JSON.stringify(await res.json())).toContain(READ_ONLY_MESSAGE)
      expect(message).toBeTruthy()
    }
    const note = await payload.findByID({ collection: 'notes', id: noteId })
    expect(note.text).toBe('original')
    expect((await payload.findGlobal({ slug: 'settings' })).motto).toBe('original')
    expect(((await payload.findByID({ collection: 'users', id: member.id })) as unknown as { name: string }).name).toBe('Cy Member')
    expect((await payload.count({ collection: 'notes', where: { text: { equals: 'new' } } })).totalDocs).toBe(0)
  })

  it('still reads, as the target', async () => {
    const jar = await masquerade(member)
    const me = await rest('GET', '/users/me', jar)
    expect(((await me.json()) as { user: { id: string } }).user.id).toBe(member.id)
    const list = await rest('GET', '/notes', jar)
    expect(list.status).toBe(200)
    expect(((await list.json()) as { docs: { id: string }[] }).docs.map((d) => d.id)).toContain(noteId)
    expect((await rest('GET', `/notes/${noteId}`, jar)).status).toBe(200)
    expect(((await (await rest('GET', '/globals/settings', jar)).json()) as { motto: string }).motto).toBe('original')
  })

  it('stays read-only when the browser drops the state cookie but keeps the borrowed session', async () => {
    const jar = await masquerade(member)
    const borrowed = { 'payload-token': jar['payload-token']! }
    expect(((await (await rest('GET', '/users/me', borrowed)).json()) as { user: { id: string } }).user.id).toBe(member.id)
    const tries = [
      rest('POST', '/notes', borrowed, { text: 'sneaky' }),
      rest('PATCH', `/notes/${noteId}`, borrowed, { text: 'sneaky' }),
      rest('DELETE', `/notes/${noteId}`, borrowed),
      rest('POST', '/globals/settings', borrowed, { motto: 'sneaky' }),
    ]
    for (const res of await Promise.all(tries)) {
      expect(res.status).toBe(403)
      expect(await errorOf(res)).toBe(READ_ONLY_MESSAGE)
    }
    expect((await payload.findByID({ collection: 'notes', id: noteId })).text).toBe('original')
    expect((await payload.findGlobal({ slug: 'settings' })).motto).toBe('original')
  })

  it('does not let the borrowed session be refreshed past its hour', async () => {
    for (const jar of [await masquerade(member), { 'payload-token': (await masquerade(member))['payload-token']! }]) {
      const res = await rest('POST', '/users/refresh-token', jar)
      expect(res.status).toBe(403)
      expect(jarOf(res)['payload-token']).toBeUndefined()
    }
    // A normal session still refreshes.
    expect((await rest('POST', '/users/refresh-token', await signIn(member))).status).toBe(200)
  })

  it('returns over REST, after which writes work again', async () => {
    const own = await signIn(admin)
    const started = jarOf(await rest('POST', `/users/${member.id}/masq`, own, {}))
    const back = await rest('POST', '/users/masq/stop', started)
    expect(await back.json()).toMatchObject({ restored: true })
    const restored = { 'payload-token': jarOf(back)['payload-token']! }
    expect(restored['payload-token']).toBe(own['payload-token'])
    expect(jarOf(back)[STATE_COOKIE]).toBe('')
    const created = await rest('POST', '/notes', restored, { text: 'after return' })
    expect(created.status).toBe(201)
  })
})

describe('read-only over GraphQL', () => {
  it('refuses mutations on collections and globals, and still answers queries', async () => {
    const jar = await masquerade(member)
    const mutations = [
      'mutation { createNote(data: { text: "new" }) { id } }',
      `mutation { updateNote(id: "${noteId}", data: { text: "changed" }) { id } }`,
      `mutation { deleteNote(id: "${noteId}") { id } }`,
      `mutation { updateUser(id: "${member.id}", data: { name: "Changed" }) { id } }`,
      'mutation { updateSetting(data: { motto: "changed" }) { motto } }',
    ]
    for (const query of mutations) {
      const res = await gql(query, jar)
      expect(res.errors?.[0]?.message).toBe(READ_ONLY_MESSAGE)
    }
    // Without the state cookie too.
    const dropped = await gql('mutation { createNote(data: { text: "sneaky" }) { id } }', { 'payload-token': jar['payload-token']! })
    expect(dropped.errors?.[0]?.message).toBe(READ_ONLY_MESSAGE)

    expect((await payload.findByID({ collection: 'notes', id: noteId })).text).toBe('original')
    expect((await payload.findGlobal({ slug: 'settings' })).motto).toBe('original')

    const read = await gql(`{ Notes { docs { id text } } Setting { motto } meUser { user { id } } }`, jar)
    expect(read.errors).toBeUndefined()
    expect(read.data).toMatchObject({ Setting: { motto: 'original' }, meUser: { user: { id: member.id } } })
    expect((read.data!.Notes as { docs: { id: string }[] }).docs.map((d) => d.id)).toContain(noteId)
  })

  it('lets the same mutation through when nobody is masquerading (control)', async () => {
    const res = await gql('mutation { createNote(data: { text: "gql control" }) { id } }', await signIn(member))
    expect(res.errors).toBeUndefined()
  })
})

describe('read-only over REST: every other write', () => {
  it('refuses restoring collection and global versions, and the restore rolls nothing back', async () => {
    const versions = await originalVersions()
    await payload.update({ collection: 'notes', id: noteId, data: { text: 'current' } })
    await payload.updateGlobal({ slug: 'settings', data: { motto: 'current' } })
    try {
      const jar = await masquerade(member)
      for (const res of [await rest('POST', `/notes/versions/${versions.note}`, jar), await rest('POST', `/globals/settings/versions/${versions.global}`, jar)]) {
        expect(res.status).toBe(403)
        expect(await errorOf(res)).toBe(READ_ONLY_MESSAGE)
      }
      // Without the state cookie too.
      const borrowed = { 'payload-token': jar['payload-token']! }
      expect((await rest('POST', `/globals/settings/versions/${versions.global}`, borrowed)).status).toBe(403)
      expect((await payload.findByID({ collection: 'notes', id: noteId })).text).toBe('current')
      expect((await payload.findGlobal({ slug: 'settings' })).motto).toBe('current')
      // Control: the same restores work for a real session.
      const own = await signIn(member)
      expect((await rest('POST', `/notes/versions/${versions.note}`, own)).status).toBe(200)
      expect((await rest('POST', `/globals/settings/versions/${versions.global}`, own)).status).toBe(200)
      expect((await payload.findGlobal({ slug: 'settings' })).motto).toBe('original')
    } finally {
      await payload.update({ collection: 'notes', id: noteId, data: { text: 'original' } })
      await payload.updateGlobal({ slug: 'settings', data: { motto: 'original' } })
    }
  })

  it('refuses unlock, forgot-password and reset-password', async () => {
    const jar = await masquerade(member)
    const { token } = { token: await payload.forgotPassword({ collection: 'users', data: { email: member.email }, disableEmail: true }) }
    const tries = [
      rest('POST', '/users/unlock', jar, { email: member.email }),
      rest('POST', '/users/forgot-password', jar, { email: member.email }),
      rest('POST', '/users/reset-password', jar, { token, password: 'a-new-password-1' }),
    ]
    for (const res of await Promise.all(tries)) {
      expect(res.status).toBe(403)
      expect(await errorOf(res)).toBe(READ_ONLY_MESSAGE)
    }
    // The password is unchanged; control: the same reset works without a masquerade.
    expect((await rest('POST', '/users/login', {}, { email: member.email, password: PW })).status).toBe(200)
    expect((await rest('POST', '/users/unlock', await signIn(member), { email: member.email })).status).toBe(200)
  })

  it('stays read-only when the borrowed token comes in an Authorization header', async () => {
    const jar = await masquerade(member)
    for (const scheme of ['JWT', 'Bearer']) {
      const request = new Request('http://localhost:3000/api/notes', {
        method: 'POST',
        headers: { Authorization: `${scheme} ${jar['payload-token']}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'by header' }),
      })
      const res = await handleEndpoints({ config, request })
      expect(res.status).toBe(403)
      expect(await errorOf(res)).toBe(READ_ONLY_MESSAGE)
    }
    expect((await payload.count({ collection: 'notes', where: { text: { equals: 'by header' } } })).totalDocs).toBe(0)
  })

  it('refuses nesting from a borrowed session even without the state cookie', async () => {
    const jar = await masquerade(admin2)
    const res = await rest('POST', `/users/${member.id}/masq`, { 'payload-token': jar['payload-token']! }, {})
    expect(res.status).toBe(400)
    expect(await errorOf(res)).toBe('Stop masquerading first.')
  })

  it('stop ends the borrowed session even without the state cookie, and restores nothing', async () => {
    const own = await signIn(admin)
    const started = jarOf(await rest('POST', `/users/${member.id}/masq`, own, {}))
    const borrowed = started['payload-token']!
    const back = await rest('POST', '/users/masq/stop', { 'payload-token': borrowed, 'payload-masq-return': started['payload-masq-return']! })
    expect(await back.json()).toMatchObject({ restored: false })
    expect(jarOf(back)['payload-token']).toBe('')
    expect((await payload.auth({ headers: new Headers({ Authorization: `JWT ${borrowed}` }) })).user).toBeNull()
  })

  it('the documented upgrade step ends a borrowed session issued before the claim existed', async () => {
    // What 0.1.0 issued: a real session of the target, with no masqBy claim.
    const collectionConfig = payload.collections.users!.config
    const target = (await payload.findByID({ collection: 'users', id: member.id, showHiddenFields: true })) as never
    const { sid } = await addSessionToUser({ collectionConfig, payload, user: target } as never)
    const { token } = await jwtSign({ fieldsToSign: getFieldsToSign({ collectionConfig, email: member.email, sid, user: target }), secret: payload.secret, tokenExpiration: 3600 })
    expect((await payload.auth({ headers: new Headers({ Authorization: `JWT ${token}` }) })).user?.id).toBe(member.id)
    // README "Upgrading": clear every user's sessions.
    await payload.db.updateMany({ collection: 'users', where: {}, data: { sessions: [] } })
    expect((await payload.auth({ headers: new Headers({ Authorization: `JWT ${token}` }) })).user).toBeNull()
  })
})

describe('canMasquerade must answer exactly true', () => {
  const masq = () => payload.config.custom!.masq as { canMasquerade: unknown }
  async function withRule<T>(rule: unknown, fn: () => Promise<T>) {
    const before = masq().canMasquerade
    masq().canMasquerade = rule
    try {
      return await fn()
    } finally {
      masq().canMasquerade = before
    }
  }
  const truthy = () => 'yes'
  const throws = () => {
    throw new Error('rule failed')
  }

  it('refuses to start on a truthy answer that is not true, or a throw (403, never 500)', async () => {
    for (const rule of [truthy, async () => 1, throws, async () => Promise.reject(new Error('rule failed'))]) {
      const res = await withRule(rule, async () => rest('POST', `/users/${member.id}/masq`, await signIn(admin), {}))
      expect(res.status).toBe(403)
      expect(jarOf(res)['payload-token']).toBeUndefined()
    }
  })

  it('refuses the search and the restore on the same answers', async () => {
    for (const rule of [truthy, throws]) {
      expect((await withRule(rule, async () => rest('GET', '/users/masq/search?q=Cy', await signIn(admin)))).status).toBe(403)
    }
    const own = await signIn(admin)
    const started = jarOf(await rest('POST', `/users/${member.id}/masq`, own, {}))
    for (const rule of [truthy, throws]) {
      const back = await withRule(rule, () => rest('POST', '/users/masq/stop', started))
      expect(back.status).toBe(200)
      expect(await back.json()).toMatchObject({ restored: false })
    }
  })

  it('marks search results allowed only on exactly true', async () => {
    const rule = ({ target }: { target?: { id: string } }) => (target ? (target.id === member.id ? 'yes' : true) : true)
    const body = (await withRule(rule, async () => (await rest('GET', '/users/masq/search', await signIn(admin))).json())) as { docs: { id: string; allowed: boolean }[] }
    expect(body.docs.find((d) => d.id === member.id)?.allowed).toBe(false)
    expect(body.docs.find((d) => d.id === admin2.id)?.allowed).toBe(true)
  })
})

describe('start never says whether a user id exists to someone who is not allowed', () => {
  type Rule = (a: { user: U; target?: U }) => unknown
  const MADE_UP = '000000000000000000000000'
  const MALFORMED = ['not-an-id', '123', '%7B%24ne%3Anull%7D', 'x'.repeat(200)]
  const users = () => payload.collections.users!.config
  const masq = () => payload.config.custom!.masq as { canMasquerade: unknown }
  const nobody = () => false
  const everyone = () => true

  /** Runs `fn` with another permission rule and another read access on users, then puts both back. */
  async function withHost<T>({ rule, read, debug = false }: { rule?: unknown; read?: unknown; debug?: boolean }, fn: () => Promise<T>) {
    const before = { rule: masq().canMasquerade, read: users().access.read, debug: payload.config.debug }
    if (rule) masq().canMasquerade = rule
    if (read) users().access.read = read as never
    payload.config.debug = debug
    try {
      return await fn()
    } finally {
      masq().canMasquerade = before.rule
      users().access.read = before.read
      payload.config.debug = before.debug
    }
  }

  /** Everything a caller gets back. */
  const answer = async (res: Response) => ({ status: res.status, body: await res.text(), headers: [...res.headers] })

  /** The answers for another real user, a made-up id and several malformed ones. */
  async function answers(jar: Jar, realId: string) {
    const out = []
    for (const id of [realId, MADE_UP, ...MALFORMED]) out.push(await answer(await rest('POST', `/users/${id}/masq`, jar, {})))
    return out
  }

  const expectAll = (got: Awaited<ReturnType<typeof answers>>, status: number, message: string) => {
    for (const a of got) expect(a).toEqual(got[0])
    expect(got[0]!.status).toBe(status)
    expect((JSON.parse(got[0]!.body) as { errors: { message: string }[] }).errors[0]!.message).toBe(message)
    expect(got[0]!.headers.map(([k]) => k)).not.toContain('set-cookie')
  }
  const REFUSED = 'You may not masquerade as this user.'
  const NOT_FOUND = 'User not found.'

  const throws = () => {
    throw new Error('rule failed')
  }
  const rules: [string, Rule][] = [
    ['says no', nobody],
    ['throws', throws],
    ['rejects', async () => Promise.reject(new Error('rule failed'))],
    ['answers a truthy value', () => 'yes'],
    ['answers nothing', () => undefined],
    ['reads the target without checking for one', ({ target }) => (target as U).role === 'nobody'],
    ['throws only when it gets a target', ({ target }) => (target ? throws() : false)],
  ]

  it.each(rules)('answers every id alike when the rule %s', async (_name, rule) => {
    const jar = await signIn(member)
    for (const read of [nobody, everyone])
      for (const debug of [false, true]) {
        const got = await withHost({ rule, read, debug }, () => answers(jar, admin.id))
        // With debug on, Payload adds a stack to the body, so it has to match too.
        expectAll(got, 403, REFUSED)
      }
  })

  it('calls neither audit hook on a refusal', async () => {
    const jar = await signIn(member)
    const before = stops.length
    const opts = payload.config.custom!.masq as { onStart?: unknown }
    const started: unknown[] = []
    const onStart = opts.onStart
    opts.onStart = (a: unknown) => void started.push(a)
    try {
      await answers(jar, admin.id)
    } finally {
      opts.onStart = onStart
    }
    expect(started).toEqual([])
    expect(stops.length).toBe(before)
  })

  it('still tells someone who is allowed that a user was not found', async () => {
    const jar = await signIn(admin)
    expectAll((await answers(jar, MADE_UP)), 404, NOT_FOUND)
  })

  describe('someone who may use masquerade, but not as this user', () => {
    // Also what a rule that only looks at the target answers when there is no target.
    const notAdmins: Rule = ({ target }) => target?.role !== 'admin'

    it('gets the not-found answer for a user they cannot read, the same as for no user', async () => {
      const jar = await signIn(member)
      for (const read of [nobody, () => ({ role: { equals: 'member' } }), throws])
        for (const debug of [false, true])
          expectAll(await withHost({ rule: notAdmins, read, debug }, () => answers(jar, admin.id)), 404, NOT_FOUND)
    })

    it('is told they may not, only for a user they can read', async () => {
      const jar = await signIn(member)
      const res = await withHost({ rule: notAdmins, read: everyone }, () => rest('POST', `/users/${admin.id}/masq`, jar, {}))
      expect(res.status).toBe(403)
      expect(await errorOf(res)).toBe(REFUSED)
    })
  })

  it('answers the same when loading a real user fails', async () => {
    const hooks = users().hooks
    const before = hooks.afterRead
    const jarMember = await signIn(member)
    const jarAdmin = await signIn(admin)
    hooks.afterRead = [
      ...(before ?? []),
      ({ doc }) => {
        if (String(doc.id) === admin2.id) throw new Error('read hook failed')
        return doc
      },
    ]
    try {
      expectAll(await answers(jarMember, admin2.id), 403, REFUSED)
      expectAll(await answers(jarAdmin, admin2.id), 404, NOT_FOUND)
    } finally {
      hooks.afterRead = before
    }
  })

  it('still starts when the rule allows the target but says no without one, even for a user they cannot read', async () => {
    const onlyCy: Rule = ({ target }) => target?.id === member.id
    const jar = await signIn(admin2)
    const res = await withHost({ rule: onlyCy, read: nobody }, () => rest('POST', `/users/${member.id}/masq`, jar, {}))
    expect(res.status).toBe(200)
    expectAll(await withHost({ rule: onlyCy, read: nobody }, () => answers(jar, admin.id)), 403, REFUSED)
  })
})

describe('start goes by the account found, however its id is spelled', () => {
  // The database reads an id's hex in either case. Letters are all that change, so the ids need at least one.
  const upper = (id: string) => id.toUpperCase()
  const mixed = (id: string) => id.replace(/[a-f]/, (c) => c.toUpperCase())
  const spellings: [string, (id: string) => string][] = [
    ['upper case', upper],
    ['mixed case', mixed],
  ]
  type Hooks = { onStart?: unknown; canMasquerade: unknown }
  const masq = () => payload.config.custom!.masq as Hooks
  const sessionsOf = async (u: U) =>
    ((await payload.findByID({ collection: 'users', id: u.id, showHiddenFields: true })) as unknown as { sessions?: unknown[] }).sessions?.length ?? 0
  const signsInAs = async (token: string) => (await payload.auth({ headers: new Headers({ Authorization: `Bearer ${token}` }) })).user?.id ?? null

  /** Runs `fn` recording who `onStart` and `canMasquerade` were asked about, then puts both back. */
  async function recording<T>(fn: () => Promise<T>) {
    const before = { onStart: masq().onStart, canMasquerade: masq().canMasquerade }
    const started: string[] = []
    const asked: string[] = []
    masq().onStart = ({ target }: { target: U }) => void started.push(String(target.id))
    masq().canMasquerade = (a: { user: U; target?: U }) => {
      if (a.target) asked.push(String(a.target.id))
      return a.user.role === 'admin'
    }
    try {
      return { result: await fn(), started, asked }
    } finally {
      Object.assign(masq(), before)
    }
  }

  it.each(spellings)('refuses yourself with your id in %s', async (_name, spell) => {
    const own = await signIn(admin)
    const id = spell(admin.id)
    expect(id).not.toBe(admin.id)
    const sessions = await sessionsOf(admin)
    const { result: res, started, asked } = await recording(() => rest('POST', `/users/${id}/masq`, own, {}))
    expect(res.status).toBe(400)
    expect(await errorOf(res)).toBe('Choose another user.')
    expect(res.headers.getSetCookie()).toEqual([])
    expect(started).toEqual([])
    expect(asked).toEqual([])
    expect(await sessionsOf(admin)).toBe(sessions)
  })

  it.each(spellings)('records the found id for a target spelled in %s, and Return ends the borrowed session', async (_name, spell) => {
    const own = await signIn(admin)
    const id = spell(member.id)
    expect(id).not.toBe(member.id)
    const { result: res, started } = await recording(() => rest('POST', `/users/${id}/masq`, own, {}))
    expect(res.status).toBe(200)
    expect(started).toEqual([member.id])
    const set = jarOf(res)
    expect(decodeState(payload.secret, set[STATE_COOKIE])).toMatchObject({ by: admin.id, as: member.id })
    const borrowed = set['payload-token']!
    expect(await signsInAs(borrowed)).toBe(member.id)
    const before = stops.length
    const back = await rest('POST', '/users/masq/stop', set)
    expect(await back.json()).toMatchObject({ restored: true, redirect: `/admin/collections/users/${member.id}` })
    expect(stops.slice(before)).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
    expect(await signsInAs(borrowed)).toBeNull()
  })

  describe('stop with a state cookie set before an upgrade', () => {
    /** Starts a masquerade as the member, then signs its state cookie again with `change` applied. */
    async function startedWith(change: { as?: string; by?: string }) {
      const res = await rest('POST', `/users/${member.id}/masq`, await signIn(admin), {})
      expect(res.status).toBe(200)
      const set = jarOf(res)
      const state = decodeState(payload.secret, set[STATE_COOKIE])!
      return { jar: { ...set, [STATE_COOKIE]: encodeState(payload.secret, { ...state, ...change }) } as Jar, borrowed: set['payload-token']! }
    }

    /**
     * Calls stop, counting the lookups of a masquerade's target (the only reads there with both `disableErrors`
     * and `showHiddenFields`). `answer`, if given, stands in for the lookup of `answer.id`.
     */
    async function stop(jar: Jar, answer?: { id: string; with: () => unknown }) {
      const real = payload.findByID.bind(payload) as (args: Record<string, unknown>) => Promise<unknown>
      const lookups: unknown[] = []
      const spy = vi.spyOn(payload, 'findByID').mockImplementation((async (args: Record<string, unknown>) => {
        if (!args.disableErrors || !args.showHiddenFields) return real(args)
        lookups.push(args.id)
        return answer && args.id === answer.id ? answer.with() : real(args)
      }) as never)
      const before = stops.length
      try {
        const res = await rest('POST', '/users/masq/stop', jar)
        expect(res.status).toBe(200)
        return { body: (await res.json()) as Record<string, unknown>, set: jarOf(res), reported: stops.slice(before), lookups }
      } finally {
        spy.mockRestore()
      }
    }

    it.each(spellings)('ends the borrowed session when the state spells the target in %s', async (_name, spell) => {
      const as = spell(member.id)
      expect(as).not.toBe(member.id)
      const { jar, borrowed } = await startedWith({ as })
      expect(await signsInAs(borrowed)).toBe(member.id)
      const { body, reported, lookups } = await stop(jar)
      expect(await signsInAs(borrowed)).toBeNull()
      expect(reported).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: member.id, expired: false, restored: true })])
      expect(body).toMatchObject({ restored: true, redirect: `/admin/collections/users/${member.id}` })
      expect(lookups).toEqual([as])
    })

    it('looks nothing up when the state and the token spell the target alike', async () => {
      const { jar, borrowed } = await startedWith({})
      const { reported, lookups } = await stop(jar)
      expect(lookups).toEqual([])
      expect(reported).toEqual([expect.objectContaining({ targetId: member.id, expired: false })])
      expect(await signsInAs(borrowed)).toBeNull()
    })

    /** Stop's answer when the state isn't shown to name this borrowed session: it stays, and the admin gets back. */
    async function expectLeftAlone(jar: Jar, borrowed: string, as: string, answer?: Parameters<typeof stop>[1]) {
      const sessions = await sessionsOf(member)
      const { body, set, reported, lookups } = await stop(jar, answer)
      expect(lookups).toEqual([as])
      expect(await signsInAs(borrowed)).toBe(member.id)
      expect(await sessionsOf(member)).toBe(sessions)
      expect(reported).toEqual([expect.objectContaining({ masqueraderId: admin.id, targetId: as, expired: true, restored: true })])
      expect(body).toMatchObject({ restored: true, redirect: `/admin/collections/users/${as}` })
      expect(set['payload-token']).toBe(jar['payload-masq-return'])
      expect(set[STATE_COOKIE]).toBe('')
    }

    it.each([['its own spelling', (id: string) => id], ...spellings])('deletes nothing when the state names another account in %s', async (_name, spell) => {
      const as = spell(admin2.id)
      const { jar, borrowed } = await startedWith({ as })
      await expectLeftAlone(jar, borrowed, as)
    })

    it('deletes nothing when the database cannot read the id in the state', async () => {
      const { jar, borrowed } = await startedWith({ as: 'not-an-id' })
      await expectLeftAlone(jar, borrowed, 'not-an-id')
    })

    it.each<[string, () => unknown]>([
      [
        'fails',
        () => {
          throw new Error('lookup failed')
        },
      ],
      ['finds nothing', () => null],
      ['hands back no id', () => ({})],
      // It reads as the member's id as text, but it isn't a string or a number.
      ['hands back an object for an id', () => ({ id: { toString: () => member.id } })],
      ['hands back a number that is not finite', () => ({ id: Number.NaN })],
    ])('deletes nothing when the lookup %s', async (_name, answer) => {
      const as = upper(member.id)
      const { jar, borrowed } = await startedWith({ as })
      await expectLeftAlone(jar, borrowed, as, { id: as, with: answer })
    })

    it('looks nothing up and deletes nothing when the state names another masquerader', async () => {
      const as = upper(member.id)
      const { jar, borrowed } = await startedWith({ as, by: admin2.id })
      const { body, reported, lookups } = await stop(jar)
      expect(lookups).toEqual([])
      expect(await signsInAs(borrowed)).toBe(member.id)
      expect(reported).toEqual([expect.objectContaining({ masqueraderId: admin2.id, targetId: as, expired: true, restored: false })])
      expect(body).toMatchObject({ restored: false, redirect: '/admin/login' })
    })
  })

  it('gives someone who is not allowed one answer for real and made-up ids in any spelling', async () => {
    const jar = await signIn(member)
    const madeUp = 'abcdefabcdefabcdefabcdef'
    const got = []
    for (const id of [admin.id, upper(admin.id), mixed(admin.id), madeUp, upper(madeUp), mixed(madeUp)]) {
      const res = await rest('POST', `/users/${id}/masq`, jar, {})
      got.push({ status: res.status, body: await res.text(), headers: [...res.headers] })
    }
    for (const a of got) expect(a).toEqual(got[0])
    expect(got[0]!.status).toBe(403)
  })
})

describe('the masqBy claim must be genuine', () => {
  it('a forged claim on a cookie token records nothing and ends nothing', async () => {
    const real = (await signIn(member))['payload-token']!
    const [head, body, sig] = real.split('.')
    const claims = { ...JSON.parse(Buffer.from(body!, 'base64url').toString('utf8')), masqBy: admin.id }
    const forged = `${head}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${sig}`
    const before = stops.length
    const request = new Request('http://localhost:3000/api/users/masq/stop', {
      method: 'POST',
      headers: { Authorization: `JWT ${real}`, cookie: `payload-token=${forged}` },
    })
    const res = await handleEndpoints({ config, request })
    expect(await res.json()).toMatchObject({ restored: false })
    expect(stops.length).toBe(before)
    // The real session is still alive.
    expect((await payload.auth({ headers: new Headers({ Authorization: `JWT ${real}` }) })).user?.id).toBe(member.id)
  })

  it('a genuine borrowed token of someone else, beside a real sign-in, records nothing and ends nothing', async () => {
    const real = (await signIn(member))['payload-token']!
    const otherBorrowed = (await masquerade(admin2))['payload-token']!
    const before = stops.length
    const request = new Request('http://localhost:3000/api/users/masq/stop', {
      method: 'POST',
      headers: { Authorization: `JWT ${real}`, cookie: `payload-token=${otherBorrowed}` },
    })
    expect(await (await handleEndpoints({ config, request })).json()).toMatchObject({ restored: false })
    expect(stops.length).toBe(before)
    expect((await payload.auth({ headers: new Headers({ Authorization: `JWT ${real}` }) })).user?.id).toBe(member.id)
  })
})
