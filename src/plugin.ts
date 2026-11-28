import type { Config, Plugin } from 'payload'

import { searchEndpoint, startEndpoint, stopEndpoint } from './endpoints.js'
import { BOOKKEEPING, ensureGuards, globalChangeGuard, globalReadOnlyGuard, noBorrowedRefresh, readOnlyGuard } from './guard.js'
import { recheckStrategy } from './recheck.js'
import { sessionsOn } from './state.js'
import type { MasqPluginOptions, ResolvedMasqOptions } from './types.js'

export { READ_ONLY_MESSAGE } from './guard.js'

const sessionsError = (collection: string, value: unknown) =>
  `payload-plugin-masq: collection "${collection}" has useSessions: ${JSON.stringify(value) ?? 'undefined'}; masq needs useSessions: true to end a borrowed session`

/**
 * Masquerade: an admin signs in as another user to see what they see.
 *
 * - The masquerader gets a real, short Payload session of the target (the same
 *   session machinery as a normal login), so every access rule applies exactly
 *   as for that user. Default one hour.
 * - Their own token waits in an httpOnly cookie sent only to the stop
 *   endpoint, and comes back only if it is still valid and they may still
 *   masquerade. The borrowed session is ended on return.
 * - A signed cookie records who is masquerading as whom, for the banner and
 *   for audit trails (`masqueraderOf(req)`).
 * - The admin gets a "Masquerade as this user" button on each user, a
 *   Masquerade view with a user search (only for people allowed to
 *   masquerade, reading with their own access), and a banner with
 *   "Return to my account". Put `<MasqueradeBanner />` in your site layout too.
 */
export const masqPlugin =
  (options: MasqPluginOptions): Plugin =>
  (config: Config): Config => {
    if (options.enabled === false) return config
    const collection = options.collection ?? 'users'
    const adminRoute = config.routes?.admin ?? '/admin'
    const resolved: ResolvedMasqOptions = {
      collection,
      canMasquerade: options.canMasquerade,
      duration: options.duration ?? 3600,
      readOnly: options.readOnly ?? true,
      requireReason: options.requireReason ?? false,
      labelField: options.labelField ?? 'email',
      searchFields: options.searchFields ?? ['email'],
      startPath: options.startPath ?? adminRoute,
      adminBanner: options.adminBanner ?? true,
      adminView: options.adminView ?? true,
      listColumn: options.listColumn ?? true,
      enabled: true,
      onStart: options.onStart,
      onStop: options.onStop,
      recheck: options.recheck,
      apiRoute: config.routes?.api ?? '/api',
      adminRoute,
    }
    const target = (config.collections ?? []).find((c) => c.slug === collection)
    if (!target) throw new Error(`payload-plugin-masq: no collection "${collection}"`)
    if (!target.auth) throw new Error(`payload-plugin-masq: collection "${collection}" is not an auth collection`)
    // The recheck and the stop endpoint end a borrowed token by deleting its session. Without sessions there is
    // nothing to delete, and a demoted masquerader would keep the token until it expires.
    // Payload turns sessions off for any falsy value and only fills in its default (true) for null or undefined.
    const useSessions = typeof target.auth === 'object' ? (target.auth as { useSessions?: unknown }).useSessions : undefined
    if (useSessions != null && useSessions !== true) throw new Error(sessionsError(collection, useSessions))
    if (options.readOnly !== undefined && typeof options.readOnly !== 'boolean') throw new Error('payload-plugin-masq: readOnly must be true or false')
    const components = config.admin?.components ?? {}
    const globals = resolved.readOnly
      ? (config.globals ?? []).map((g) => ({
          ...g,
          hooks: {
            ...g.hooks,
            beforeOperation: [...(g.hooks?.beforeOperation ?? []), globalReadOnlyGuard],
            beforeChange: [...(g.hooks?.beforeChange ?? []), globalChangeGuard],
          },
        }))
      : config.globals
    const onInit = config.onInit
    return {
      ...config,
      onInit: async (payload) => {
        // Another plugin or the host can still turn sessions off after this point, so check the built config too.
        if (!sessionsOn(payload, collection))
          throw new Error(sessionsError(collection, (payload.collections[collection as never]?.config.auth as { useSessions?: unknown } | undefined)?.useSessions))
        await onInit?.(payload)
        // Collections and globals that Payload or later plugins add, or rebuild, only exist from here on. The guards
        // go on all of them, and Payload doesn't start unless every one is confirmed.
        const { ok, missing } = ensureGuards(payload)
        if (!ok) throw new Error(`payload-plugin-masq: read-only masquerade could not be put in place on ${missing.join(', ')}`)
      },
      globals,
      custom: { ...config.custom, masq: resolved },
      admin: {
        ...config.admin,
        components: {
          ...components,
          header: [...(components.header ?? []), ...(resolved.adminBanner ? ['@extantape/payload-plugin-masq/rsc#AdminMasqueradeBanner'] : [])],
          afterNavLinks: [...(components.afterNavLinks ?? []), ...(resolved.adminView ? ['@extantape/payload-plugin-masq/rsc#MasqueradeNavLink'] : [])],
          views: {
            ...components.views,
            ...(resolved.adminView ? { masquerade: { Component: '@extantape/payload-plugin-masq/rsc#MasqueradeView', path: '/masquerade' } } : {}),
          },
        },
      },
      collections: (config.collections ?? []).map((c) => {
        const guarded = resolved.readOnly && !BOOKKEEPING.has(c.slug)
        const hooks = guarded ? { ...c.hooks, beforeOperation: [...(c.hooks?.beforeOperation ?? []), readOnlyGuard] } : c.hooks
        if (c.slug !== collection) return { ...c, hooks }
        const columns = c.admin?.defaultColumns
        // Our recheck goes first, so a revoked borrowed session is gone before Payload's JWT strategy reads it.
        const auth = typeof c.auth === 'object' ? { ...c.auth, strategies: [recheckStrategy, ...(c.auth.strategies ?? [])] } : { strategies: [recheckStrategy] }
        return {
          ...c,
          auth,
          hooks: { ...hooks, beforeOperation: [...(hooks?.beforeOperation ?? []), noBorrowedRefresh] },
          admin: resolved.listColumn && columns ? { ...c.admin, defaultColumns: [...columns, 'masq'] } : c.admin,
          endpoints: [stopEndpoint, searchEndpoint, startEndpoint, ...(c.endpoints || [])],
          fields: [
            {
              name: 'masq',
              type: 'ui',
              label: 'Masquerade',
              admin: {
                position: 'sidebar',
                components: { Field: '@extantape/payload-plugin-masq/rsc#MasqueradeField', Cell: '@extantape/payload-plugin-masq/rsc#MasqueradeCell' },
              },
            },
            ...c.fields,
          ],
        }
      }),
    }
  }
