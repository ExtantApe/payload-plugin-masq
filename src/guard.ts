import { APIError, type CollectionBeforeOperationHook, type GlobalBeforeChangeHook, type GlobalBeforeOperationHook, type Payload, type PayloadRequest } from 'payload'

import { recheckStrategy } from './recheck.js'
import { borrowedBy, isMasquerading } from './state.js'
import type { ResolvedMasqOptions } from './types.js'

export const READ_ONLY_MESSAGE = 'Masquerade is read-only: nothing can be created, changed or deleted while masquerading.'

/** Payload's own bookkeeping, written while simply looking around the admin. Left writable. */
export const BOOKKEEPING = new Set(['payload-preferences', 'payload-locked-documents'])

/** Collections the read-only guard is not put on: the bookkeeping above, and migrations, which only Payload itself writes. */
export const UNGUARDED = new Set([...BOOKKEEPING, 'payload-migrations'])

/**
 * Every collection operation in Payload 3.92 that writes and runs `beforeOperation`. Login
 * (it only records the sign-in) and refresh (refused separately) are left out.
 */
const COLLECTION_WRITES = new Set(['create', 'update', 'delete', 'restoreVersion', 'unlock', 'forgotPassword', 'resetPassword'])

/** Global operations that write. A global restore skips `beforeChange`, so the guard sits here. */
const GLOBAL_WRITES = new Set(['update', 'restoreVersion'])

const readOnlyError = () => new APIError(READ_ONLY_MESSAGE, 403, undefined, true)

/** Read-only masquerade: refuse writes while masquerading (the plugin's own writes are marked internal). */
export const readOnlyGuard: CollectionBeforeOperationHook = ({ args, operation, req }) => {
  if (req.context?.masqInternal) return args
  if (COLLECTION_WRITES.has(operation) && isMasquerading(req.payload, req.headers)) throw readOnlyError()
  return args
}

export const globalReadOnlyGuard: GlobalBeforeOperationHook = ({ args, operation, req }) => {
  if (req.context?.masqInternal) return args
  if (GLOBAL_WRITES.has(operation) && isMasquerading(req.payload, req.headers)) throw readOnlyError()
  return args
}

export const globalChangeGuard: GlobalBeforeChangeHook = ({ data, req }) => {
  if (!req.context?.masqInternal && isMasquerading(req.payload, req.headers)) throw readOnlyError()
  return data
}

/** A borrowed session ends on time: it can't be refreshed (the admin refreshes tokens while you're active). */
export const noBorrowedRefresh: CollectionBeforeOperationHook = ({ args, operation, req }) => {
  if (operation === 'refresh' && borrowedBy(req.payload, req.headers)) throw new APIError('A masquerade session can’t be extended.', 403, undefined, true)
  return args
}

type JobsAccess = (args: { req: PayloadRequest }) => unknown
const JOBS_ACCESS = ['run', 'queue', 'cancel'] as const
const jobsGuards = new WeakSet<object>()

/**
 * Jobs access that answers 403 while masquerading and otherwise asks the access the host set. Without one, it
 * answers as Payload would: running needs a signed-in user, queueing and cancelling are allowed.
 */
function guardJobsAccess(payload: Payload, kind: (typeof JOBS_ACCESS)[number], original: JobsAccess | undefined): JobsAccess {
  const guarded: JobsAccess = async (args) => {
    if (isMasquerading(payload, args.req?.headers)) throw readOnlyError()
    if (original) return original(args)
    return kind === 'run' ? Boolean(args.req?.user) : true
  }
  jobsGuards.add(guarded)
  return guarded
}

const JOBS_LOCAL = ['queue', 'run', 'runByID', 'cancel', 'cancelByID', 'handleSchedules'] as const
type JobsLocal = (args?: { req?: Partial<PayloadRequest> }) => Promise<unknown>

/**
 * The jobs Local API, refusing a call made with a masquerading request. Some of these calls write straight to the
 * database without running collection hooks or access, so the collection guard alone can't see them.
 */
function guardJobsLocal(payload: Payload, original: JobsLocal): JobsLocal {
  const guarded: JobsLocal = async (args) => {
    if (args?.req && !args.req.context?.masqInternal && isMasquerading(payload, args.req.headers)) throw readOnlyError()
    return original(args)
  }
  jobsGuards.add(guarded)
  return guarded
}

/** The list with the hook first, or the list unchanged when the hook is already in it. */
const withFirst = <T>(list: T[] | undefined, hook: T): T[] => (list?.includes(hook) ? list : [hook, ...(list ?? [])])

type Hooks = Record<string, unknown[] | undefined>

/**
 * Puts the guards on Payload as it was finally built: every collection and global, including the ones Payload
 * adds itself and the ones other plugins add or rebuild after Masq, plus the jobs access. Safe to run again.
 */
export function installGuards(payload: Payload, opts: ResolvedMasqOptions) {
  for (const { config } of Object.values(payload.collections ?? {})) {
    const hooks = ((config as { hooks?: Hooks }).hooks ??= {}) as Hooks
    if (opts.readOnly && !UNGUARDED.has(config.slug)) hooks.beforeOperation = withFirst(hooks.beforeOperation, readOnlyGuard)
    if (config.slug === opts.collection) hooks.beforeOperation = withFirst(hooks.beforeOperation, noBorrowedRefresh)
  }
  if (!opts.readOnly) return
  for (const global of payload.globals?.config ?? []) {
    const hooks = ((global as { hooks?: Hooks }).hooks ??= {}) as Hooks
    hooks.beforeOperation = withFirst(hooks.beforeOperation, globalReadOnlyGuard)
    hooks.beforeChange = withFirst(hooks.beforeChange, globalChangeGuard)
  }
  const jobs = payload.config?.jobs as { access?: Record<string, JobsAccess | undefined> } | undefined
  if (jobs) {
    const access = (jobs.access ??= {})
    for (const kind of JOBS_ACCESS) if (!jobsGuards.has(access[kind] as object)) access[kind] = guardJobsAccess(payload, kind, access[kind])
  }
  const local = payload.jobs as unknown as Record<string, JobsLocal | undefined> | undefined
  if (local) {
    for (const name of JOBS_LOCAL) {
      const fn = local[name]
      if (typeof fn === 'function' && !jobsGuards.has(fn)) local[name] = guardJobsLocal(payload, fn)
    }
  }
}

/** What is missing from the guards on Payload as it is now; empty when everything is in place. */
export function missingGuards(payload: Payload, opts: ResolvedMasqOptions): string[] {
  const missing: string[] = []
  const has = (list: unknown, hook: unknown) => Array.isArray(list) && list.includes(hook)
  if (!payload.authStrategies?.some((s) => s.authenticate === recheckStrategy.authenticate)) missing.push('the masquerade sign-in check')
  const collections = Object.values(payload.collections ?? {})
  if (!collections.some(({ config }) => config.slug === opts.collection)) missing.push(`collection "${opts.collection}"`)
  for (const { config } of collections) {
    const before = (config as { hooks?: Hooks }).hooks?.beforeOperation
    if (opts.readOnly && !UNGUARDED.has(config.slug) && !has(before, readOnlyGuard)) missing.push(`collection "${config.slug}"`)
    if (config.slug === opts.collection && !has(before, noBorrowedRefresh)) missing.push(`refresh refusal on "${config.slug}"`)
  }
  if (!opts.readOnly) return missing
  for (const global of payload.globals?.config ?? []) {
    const hooks = (global as { hooks?: Hooks }).hooks
    if (!has(hooks?.beforeOperation, globalReadOnlyGuard) || !has(hooks?.beforeChange, globalChangeGuard)) missing.push(`global "${global.slug}"`)
  }
  const access = (payload.config?.jobs as { access?: Record<string, unknown> } | undefined)?.access
  for (const kind of JOBS_ACCESS) if (!access || !jobsGuards.has(access[kind] as object)) missing.push(`jobs ${kind} access`)
  const local = payload.jobs as unknown as Record<string, unknown> | undefined
  for (const name of JOBS_LOCAL) {
    const fn = local?.[name]
    if (typeof fn === 'function' && !jobsGuards.has(fn)) missing.push(`jobs.${name}`)
  }
  return missing
}

/**
 * Puts the guards in place if they aren't, checks them, and records the answer in `custom.masq.guarded`. Answers
 * true only when every guard is confirmed; an error on the way is a no.
 */
export function ensureGuards(payload: Payload): { ok: boolean; missing: string[] } {
  const opts = payload.config?.custom?.masq as ResolvedMasqOptions | undefined
  if (!opts) return { ok: false, missing: ['masquerade options'] }
  let missing: string[]
  try {
    installGuards(payload, opts)
    missing = missingGuards(payload, opts)
  } catch (err) {
    missing = [`an error: ${err instanceof Error ? err.message : String(err)}`]
  }
  opts.guarded = missing.length === 0
  return { ok: opts.guarded, missing }
}
