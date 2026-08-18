import { mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  renderToolsSdk,
  type JsonValue,
  type ToolRunContext,
} from '@deepseek-ai/dsh-tools'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { alternativesFor } from '../src/alternatives.js'
import {
  createDepCheckTool,
  DepCheckError,
  executeDepCheck,
  type DepCheckResult,
} from '../src/tool.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  vi.unstubAllGlobals()
  await Promise.all(temporaryDirectories.splice(0).map(path => rm(path, {
    recursive: true,
    force: true,
  })))
})

describe('lightweight alternatives', () => {
  it('returns curated copies with migration caveats', () => {
    const alternatives = alternativesFor('moment')
    expect(alternatives).toEqual([expect.objectContaining({
      name: 'dayjs',
      caveat: expect.stringContaining('插件'),
    })])
    alternatives[0]!.name = 'changed'
    expect(alternativesFor('moment')[0]?.name).toBe('dayjs')
    expect(alternativesFor('react')).toEqual([])
  })
})

describe('dep_check canonical tool', () => {
  it('declares an rc.7 canonical schema and renders the exact JSON result', async () => {
    const tool = createDepCheckTool({ fetch: completeAuditFetch() })
    expect(tool.name).toBe('dep_check')
    expect(tool.parameters).toMatchObject({
      type: 'object',
      properties: {
        packages: { type: 'array' },
        includePackageJson: { type: 'boolean', default: false },
        packageJsonPath: { type: 'string', default: 'package.json' },
      },
    })
    expect(tool.output.schema).toMatchObject({
      type: 'object',
      additionalProperties: false,
      properties: {
        schemaVersion: { const: 1 },
        packages: { type: 'array' },
      },
    })
    const codeModeSdk = renderToolsSdk([{
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      output: tool.output.schema,
    }])
    expect(codeModeSdk).toContain('dep_check')
    expect(codeModeSdk).toContain('schemaVersion: 1')
    expect(codeModeSdk).toContain('alternatives:')

    const value = await tool.execute(
      { packages: ['moment@^2', 'dayjs'] },
      execution(process.cwd()),
    ) as DepCheckResult
    const content = tool.output.render(
      { packages: ['moment@^2', 'dayjs'] },
      value as unknown as JsonValue,
    )

    expect(value).toMatchObject({
      schemaVersion: 1,
      verdict: 'allow',
      packageJsonPath: null,
      summary: { total: 2, allow: 2, skipped: 0 },
    })
    expect(value.packages[0]).toMatchObject({
      name: 'moment',
      requested: '^2',
      resolvedVersion: '2.30.1',
      alternatives: [{ name: 'dayjs' }],
    })
    expect(content).toEqual([{
      type: 'text',
      text: JSON.stringify(value, null, 2),
    }])
  })

  it('requires an explicit audit mode and gives semantic failures stable codes', async () => {
    await expect(executeDepCheck({}, execution(process.cwd())))
      .rejects.toMatchObject({
        name: 'DepCheckError',
        code: 'DEP_CHECK_INPUT_INVALID',
      })
    await expect(executeDepCheck(
      { packages: ['file:../local'] },
      execution(process.cwd()),
    )).rejects.toBeInstanceOf(DepCheckError)
  })

  it('propagates caller cancellation before filesystem or network work', async () => {
    const controller = new AbortController()
    controller.abort(new DOMException('cancelled', 'AbortError'))

    await expect(executeDepCheck(
      { packages: ['react'] },
      execution(process.cwd(), controller.signal),
    )).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('package.json dependency audit', () => {
  it('audits all dependency sections from the default workspace manifest', async () => {
    const workspace = await temporaryDirectory()
    await writeFile(join(workspace, 'package.json'), JSON.stringify({
      dependencies: {
        moment: '^2',
      },
      devDependencies: {
        dayjs: 'latest',
      },
      optionalDependencies: {
        local: 'file:../local',
      },
      peerDependencies: {
        moment: '^2',
      },
    }))

    const result = await executeDepCheck(
      { includePackageJson: true },
      execution(workspace),
      { fetch: completeAuditFetch() },
    )

    expect(result.packageJsonPath).toBe(await realpath(join(workspace, 'package.json')))
    expect(result.summary).toMatchObject({ total: 2, allow: 2, skipped: 1 })
    expect(result.packages.map(pkg => pkg.name)).toEqual(['moment', 'dayjs'])
    expect(result.packages[0]?.sources).toEqual([
      { kind: 'dependency', section: 'dependencies', declaredName: 'moment' },
      { kind: 'dependency', section: 'peerDependencies', declaredName: 'moment' },
    ])
    expect(result.skipped).toEqual([{
      name: 'local',
      requested: 'file:../local',
      source: {
        kind: 'dependency',
        section: 'optionalDependencies',
        declaredName: 'local',
      },
      reason: 'non-registry-spec',
    }])
  })

  it('rejects lexical escapes and symlinks that leave the workspace', async () => {
    const workspace = await temporaryDirectory()
    const outside = await temporaryDirectory()
    await writeFile(join(outside, 'package.json'), '{}')
    await symlink(outside, join(workspace, 'linked'))

    await expect(executeDepCheck(
      { includePackageJson: true, packageJsonPath: '../package.json' },
      execution(workspace),
    )).rejects.toMatchObject({ code: 'DEP_CHECK_PATH_DENIED' })
    await expect(executeDepCheck(
      { includePackageJson: true, packageJsonPath: 'linked/package.json' },
      execution(workspace),
    )).rejects.toMatchObject({ code: 'DEP_CHECK_PATH_DENIED' })
  })

  it('rejects malformed manifests with a stable error code', async () => {
    const workspace = await temporaryDirectory()
    await writeFile(join(workspace, 'package.json'), '{not json')

    await expect(executeDepCheck(
      { includePackageJson: true },
      execution(workspace),
    )).rejects.toMatchObject({ code: 'DEP_CHECK_MANIFEST_INVALID' })
  })
})

function execution(cwd: string, signal = new AbortController().signal): ToolRunContext {
  return {
    signal,
    agent: {
      session: { header: { cwd } },
    },
  } as unknown as ToolRunContext
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-install-guard-'))
  temporaryDirectories.push(directory)
  return directory
}

function completeAuditFetch(): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input)
    if (url.includes('registry.npmjs.org')) {
      const name = decodeURIComponent(url.split('/').at(-1) ?? '')
      const version = name === 'moment' ? '2.30.1' : '1.11.13'
      return jsonResponse({
        'dist-tags': { latest: version },
        versions: {
          [version]: { license: 'MIT' },
        },
        time: { created: '2020-01-01T00:00:00.000Z' },
        maintainers: [{ name: 'maintainer' }],
      })
    }
    if (url.includes('api.osv.dev')) return jsonResponse({})
    if (url.includes('bundlephobia.com')) {
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
