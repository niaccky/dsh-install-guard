import type { Context } from '@deepseek-ai/cordis'
import type { PreToolDecision, ToolDefinition, ToolExecution } from '@deepseek-ai/dsh-tools'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { apply, Config, type Config as PluginConfig } from '../src/index.js'

type PreExecuteHandler = (
  exec: ToolExecution,
  next: () => Promise<PreToolDecision>,
) => Promise<PreToolDecision>

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('tools/pre-execute interception', () => {
  it('registers dep_check through the Cordis-owned tools service', () => {
    const register = vi.fn((_definition: ToolDefinition) => () => undefined)
    registerPlugin({}, register)

    expect(register).toHaveBeenCalledOnce()
    expect(register.mock.calls[0]?.[0]).toMatchObject({
      name: 'dep_check',
      output: {
        schema: { type: 'object' },
        render: expect.any(Function),
      },
    })
  })

  it('delegates non-install and non-bash calls unchanged', async () => {
    const handler = registerPlugin()
    const next = vi.fn(async (): Promise<PreToolDecision> => ({ kind: 'allow' }))

    await expect(handler(execution('read_file', { path: 'package.json' }), next))
      .resolves.toEqual({ kind: 'allow' })
    await expect(handler(execution('bash', { command: 'npm ci' }), next))
      .resolves.toEqual({ kind: 'allow' })
    expect(next).toHaveBeenCalledTimes(2)
  })

  it.each([
    ['deny', 'HIGH'],
    ['ask', 'MODERATE'],
  ] as const)('returns %s without calling downstream for %s findings', async (expected, severity) => {
    vi.stubGlobal('fetch', auditFetch(severity))
    const handler = registerPlugin()
    const next = vi.fn(async (): Promise<PreToolDecision> => ({ kind: 'allow' }))

    const decision = await handler(
      execution('bash', { command: 'npm install vulnerable@^1' }),
      next,
    )

    expect(decision.kind).toBe(expected)
    expect(next).not.toHaveBeenCalled()
    if (decision.kind !== 'allow') expect(decision.reason).toContain('CVE-2026-1234')
  })

  it('calls downstream when OSV reports no findings', async () => {
    vi.stubGlobal('fetch', auditFetch())
    const handler = registerPlugin()
    const next = vi.fn(async (): Promise<PreToolDecision> => ({ kind: 'allow' }))

    await expect(handler(
      execution('bash', { command: 'npm i clean' }),
      next,
    )).resolves.toEqual({ kind: 'allow' })
    expect(next).toHaveBeenCalledOnce()
  })

  it('passes plugin config to the audit and honors the allowlist', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    const handler = registerPlugin({ allowPackages: ['trusted'] })
    const next = vi.fn(async (): Promise<PreToolDecision> => ({ kind: 'allow' }))

    await expect(handler(
      execution('bash', { command: 'npm i trusted' }),
      next,
    )).resolves.toEqual({ kind: 'allow' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('Schemastery config', () => {
  it('supplies safe defaults and validates custom thresholds', () => {
    expect(Config()).toEqual({
      denySeverity: 'high',
      askSeverity: 'unknown',
      blockedLicenses: ['GPL', 'AGPL'],
      allowPackages: [],
      maxBundleSizeKb: 20,
      minWeeklyDownloads: 100,
      minPackageAgeDays: 30,
      typosquatMaxDistance: 1,
      failClosed: false,
    })
    expect(Config({
      denySeverity: 'critical',
      askSeverity: 'medium',
      blockedLicenses: ['SSPL-1.0'],
      allowPackages: ['@internal/*'],
      maxBundleSizeKb: 50,
      minWeeklyDownloads: 500,
      minPackageAgeDays: 90,
      typosquatMaxDistance: 2,
      failClosed: true,
    })).toMatchObject({
      denySeverity: 'critical',
      askSeverity: 'medium',
      failClosed: true,
      maxBundleSizeKb: 50,
    })
    expect(() => Config({ maxBundleSizeKb: -1 })).toThrow()
  })
})

function registerPlugin(
  config: PluginConfig = {},
  register: (definition: ToolDefinition) => () => void = () => () => undefined,
): PreExecuteHandler {
  let handler: PreExecuteHandler | undefined
  const ctx = {
    logger: { warn: vi.fn() },
    tools: { register },
    on(event: string, candidate: PreExecuteHandler) {
      if (event === 'tools/pre-execute') handler = candidate
      return () => undefined
    },
  } as unknown as Context
  apply(ctx, config)
  if (handler === undefined) throw new Error('plugin did not register tools/pre-execute')
  return handler
}

function execution(name: string, argumentsValue: unknown): ToolExecution {
  return {
    name,
    arguments: argumentsValue,
    signal: new AbortController().signal,
  } as unknown as ToolExecution
}

function auditFetch(severity?: string): typeof fetch {
  return vi.fn<typeof fetch>(async (input) => {
    if (String(input).includes('registry.npmjs.org')) {
      return jsonResponse({
        'dist-tags': { latest: '1.2.3' },
        versions: { '1.2.3': { license: 'MIT' } },
        time: { created: '2020-01-01T00:00:00.000Z' },
        maintainers: [{ name: 'maintainer' }],
      })
    }
    if (String(input).includes('api.osv.dev')) {
      return jsonResponse(severity === undefined ? {} : {
        vulns: [{
          id: 'GHSA-test',
          aliases: ['CVE-2026-1234'],
          summary: 'Test advisory',
          database_specific: { severity },
        }],
      })
    }
    if (String(input).includes('bundlephobia.com')) {
      return jsonResponse({
        size: 10_000,
        gzip: 5_000,
        hasJSModule: true,
        hasSideEffects: false,
      })
    }
    return jsonResponse({ downloads: 1_000_000 })
  })
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
