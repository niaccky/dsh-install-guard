import { readFile, realpath, stat } from 'node:fs/promises'
import { basename, isAbsolute, relative, resolve, sep } from 'node:path'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import { defineTool, type ToolDefinition, type ToolRunContext } from '@deepseek-ai/dsh-tools'
import { alternativesFor, type LightweightAlternative } from './alternatives.js'
import {
  auditPackages,
  packageAuditVerdict,
  type AuditError,
  type AuditOptions,
  type AuditVerdict,
  type PackageAudit,
} from './audit/index.js'
import { parsePackageSpec, type InstallRequest } from './parse.js'

const DEPENDENCY_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const
const MAX_PACKAGE_COUNT = 1_000
const MAX_PACKAGE_JSON_BYTES = 1_000_000
const AUDIT_BATCH_SIZE = 8

export type DependencySection = typeof DEPENDENCY_SECTIONS[number]
export type DepCheckErrorCode =
  | 'DEP_CHECK_INPUT_INVALID'
  | 'DEP_CHECK_PATH_DENIED'
  | 'DEP_CHECK_MANIFEST_NOT_FOUND'
  | 'DEP_CHECK_MANIFEST_INVALID'
  | 'DEP_CHECK_MANIFEST_TOO_LARGE'

export class DepCheckError extends HarnessError {
  constructor(code: DepCheckErrorCode, message: string, options?: ErrorOptions) {
    super(message, code, options)
  }
}

export interface DepCheckSource {
  kind: 'argument' | 'dependency'
  section: DependencySection | null
  declaredName: string
}

export interface DepCheckSkipped {
  name: string
  requested: string
  source: DepCheckSource
  reason: 'non-registry-spec' | 'invalid-package-spec'
}

export interface DepCheckPackage {
  name: string
  requested: string | null
  resolvedVersion: string | null
  verdict: AuditVerdict
  degraded: boolean
  whitelisted: boolean
  sources: DepCheckSource[]
  vulnerabilities: Array<{
    id: string
    aliases: string[]
    summary: string
    severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
    score: number | null
  }>
  license: {
    declared: string | null
    status: 'allowed' | 'blocked' | 'missing'
    blockedLicenses: string[]
  } | null
  bundleSize: {
    sizeBytes: number
    gzipBytes: number
    hasJsModule: boolean
    hasSideEffects: boolean
    treeShakeable: boolean
  } | null
  health: {
    weeklyDownloads: number
    ageDays: number | null
    maintainerCount: number | null
    similarPopularPackage: string | null
    issues: Array<{
      kind: 'deprecated' | 'no-maintainers' | 'young-and-unpopular' | 'typosquatting'
      message: string
    }>
  } | null
  errors: AuditError[]
  warnings: string[]
  alternatives: LightweightAlternative[]
}

export interface DepCheckResult {
  schemaVersion: 1
  verdict: AuditVerdict
  workspace: string
  packageJsonPath: string | null
  summary: {
    total: number
    allow: number
    ask: number
    deny: number
    degraded: number
    skipped: number
  }
  packages: DepCheckPackage[]
  skipped: DepCheckSkipped[]
}

interface Candidate {
  request: InstallRequest
  sources: DepCheckSource[]
}

interface ManifestRequests {
  path: string
  candidates: Candidate[]
  skipped: DepCheckSkipped[]
}

const SOURCE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    kind: { type: 'string', enum: ['argument', 'dependency'], required: true },
    section: {
      oneOf: [
        { type: 'string', enum: DEPENDENCY_SECTIONS },
        { type: 'null' },
      ],
      required: true,
    },
    declaredName: { type: 'string', required: true },
  },
} as const

const OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    schemaVersion: { type: 'integer', const: 1, required: true },
    verdict: { type: 'string', enum: ['allow', 'ask', 'deny'], required: true },
    workspace: { type: 'string', required: true },
    packageJsonPath: {
      oneOf: [{ type: 'string' }, { type: 'null' }],
      required: true,
    },
    summary: {
      type: 'object',
      additionalProperties: false,
      required: true,
      properties: {
        total: { type: 'integer', required: true },
        allow: { type: 'integer', required: true },
        ask: { type: 'integer', required: true },
        deny: { type: 'integer', required: true },
        degraded: { type: 'integer', required: true },
        skipped: { type: 'integer', required: true },
      },
    },
    packages: {
      type: 'array',
      required: true,
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          name: { type: 'string', required: true },
          requested: {
            oneOf: [{ type: 'string' }, { type: 'null' }],
            required: true,
          },
          resolvedVersion: {
            oneOf: [{ type: 'string' }, { type: 'null' }],
            required: true,
          },
          verdict: { type: 'string', enum: ['allow', 'ask', 'deny'], required: true },
          degraded: { type: 'boolean', required: true },
          whitelisted: { type: 'boolean', required: true },
          sources: { type: 'array', items: SOURCE_SCHEMA, required: true },
          vulnerabilities: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                id: { type: 'string', required: true },
                aliases: { type: 'array', items: { type: 'string' }, required: true },
                summary: { type: 'string', required: true },
                severity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low', 'unknown'],
                  required: true,
                },
                score: {
                  oneOf: [{ type: 'number' }, { type: 'null' }],
                  required: true,
                },
              },
            },
          },
          license: {
            oneOf: [
              { type: 'null' },
              {
                type: 'object',
                additionalProperties: false,
                properties: {
                  declared: {
                    oneOf: [{ type: 'string' }, { type: 'null' }],
                    required: true,
                  },
                  status: {
                    type: 'string',
                    enum: ['allowed', 'blocked', 'missing'],
                    required: true,
                  },
                  blockedLicenses: {
                    type: 'array',
                    items: { type: 'string' },
                    required: true,
                  },
                },
              },
            ],
            required: true,
          },
          bundleSize: {
            oneOf: [
              { type: 'null' },
              {
                type: 'object',
                additionalProperties: false,
                properties: {
                  sizeBytes: { type: 'number', required: true },
                  gzipBytes: { type: 'number', required: true },
                  hasJsModule: { type: 'boolean', required: true },
                  hasSideEffects: { type: 'boolean', required: true },
                  treeShakeable: { type: 'boolean', required: true },
                },
              },
            ],
            required: true,
          },
          health: {
            oneOf: [
              { type: 'null' },
              {
                type: 'object',
                additionalProperties: false,
                properties: {
                  weeklyDownloads: { type: 'integer', required: true },
                  ageDays: {
                    oneOf: [{ type: 'number' }, { type: 'null' }],
                    required: true,
                  },
                  maintainerCount: {
                    oneOf: [{ type: 'integer' }, { type: 'null' }],
                    required: true,
                  },
                  similarPopularPackage: {
                    oneOf: [{ type: 'string' }, { type: 'null' }],
                    required: true,
                  },
                  issues: {
                    type: 'array',
                    required: true,
                    items: {
                      type: 'object',
                      additionalProperties: false,
                      properties: {
                        kind: {
                          type: 'string',
                          enum: ['deprecated', 'no-maintainers', 'young-and-unpopular', 'typosquatting'],
                          required: true,
                        },
                        message: { type: 'string', required: true },
                      },
                    },
                  },
                },
              },
            ],
            required: true,
          },
          errors: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                check: {
                  type: 'string',
                  enum: ['registry', 'osv', 'size', 'health'],
                  required: true,
                },
                message: { type: 'string', required: true },
              },
            },
          },
          warnings: { type: 'array', items: { type: 'string' }, required: true },
          alternatives: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                name: { type: 'string', required: true },
                reason: { type: 'string', required: true },
                caveat: { type: 'string', required: true },
              },
            },
          },
        },
      },
    },
    skipped: {
      type: 'array',
      required: true,
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          name: { type: 'string', required: true },
          requested: { type: 'string', required: true },
          source: { ...SOURCE_SCHEMA, required: true },
          reason: {
            type: 'string',
            enum: ['non-registry-spec', 'invalid-package-spec'],
            required: true,
          },
        },
      },
    },
  },
} as const

/**
 * Build the model-callable dependency audit tool. The returned canonical value
 * is a domain DTO; Native mode receives its JSON rendering while Code Mode
 * receives the validated object directly.
 */
export function createDepCheckTool(options: AuditOptions = {}): ToolDefinition {
  return defineTool({
    name: 'dep_check',
    description: 'Audit one or more npm package specs, or explicitly audit every dependency in a workspace package.json, for vulnerabilities, license, bundle size, health, and lighter alternatives. Pass multiple packages to compare them.',
    parameters: {
      packages: {
        type: 'array',
        items: { type: 'string' },
        description: 'npm registry package specs to audit, for example ["moment@2.30.1", "dayjs@latest"].',
      },
      includePackageJson: {
        type: 'boolean',
        default: false,
        description: 'Set true to audit dependencies, devDependencies, optionalDependencies, and peerDependencies from package.json. The manifest is never scanned implicitly.',
      },
      packageJsonPath: {
        type: 'string',
        default: 'package.json',
        description: 'package.json path inside the current workspace. Used only when includePackageJson is true; defaults to the workspace package.json.',
      },
    },
    output: {
      schema: OUTPUT_SCHEMA,
      render: (_args, value) => [{
        type: 'text',
        text: JSON.stringify(value, null, 2),
      }],
      presentationMeta: (_args, value) => ({
        verdict: value.verdict,
        total: value.summary.total,
        degraded: value.summary.degraded,
        skipped: value.summary.skipped,
      }),
    },
    presentCall: args => ({
      card: 'generic',
      kind: 'read',
      title: args.includePackageJson === true
        ? `Audit dependencies in ${args.packageJsonPath ?? 'package.json'}`
        : `Audit ${args.packages?.length ?? 0} npm package(s)`,
      ...(args.includePackageJson === true
        ? { locations: [{ path: args.packageJsonPath ?? 'package.json' }] }
        : {}),
    }),
    async execute(args, exec): Promise<DepCheckResult> {
      return executeDepCheck(args, exec, options)
    },
  })
}

export async function executeDepCheck(
  args: {
    packages?: string[]
    includePackageJson?: boolean
    packageJsonPath?: string
  },
  exec: ToolRunContext,
  options: AuditOptions = {},
): Promise<DepCheckResult> {
  throwIfAborted(exec.signal)
  const packageSpecs = args.packages ?? []
  if (packageSpecs.length === 0 && args.includePackageJson !== true) {
    throw new DepCheckError(
      'DEP_CHECK_INPUT_INVALID',
      'dep_check requires a non-empty packages array or includePackageJson: true',
    )
  }
  if (packageSpecs.length > MAX_PACKAGE_COUNT) {
    throw new DepCheckError(
      'DEP_CHECK_INPUT_INVALID',
      `dep_check accepts at most ${MAX_PACKAGE_COUNT} package specs per call`,
    )
  }
  if (args.includePackageJson !== true && args.packageJsonPath !== undefined) {
    throw new DepCheckError(
      'DEP_CHECK_INPUT_INVALID',
      'packageJsonPath requires includePackageJson: true',
    )
  }

  const workspace = resolve(exec.agent?.session.header.cwd ?? process.cwd())
  const candidateMap = new Map<string, Candidate>()
  const invalidSpecs: string[] = []
  for (const rawSpec of packageSpecs) {
    const raw = rawSpec.trim()
    const request = raw === '' ? undefined : parsePackageSpec(raw)
    if (request === undefined) {
      invalidSpecs.push(rawSpec)
      continue
    }
    addCandidate(candidateMap, request, {
      kind: 'argument',
      section: null,
      declaredName: request.name,
    })
  }
  if (invalidSpecs.length > 0) {
    throw new DepCheckError(
      'DEP_CHECK_INPUT_INVALID',
      `unsupported or invalid npm package spec(s): ${invalidSpecs.join(', ')}`,
    )
  }

  let packageJsonPath: string | null = null
  let skipped: DepCheckSkipped[] = []
  if (args.includePackageJson === true) {
    const manifest = await readManifestRequests(
      workspace,
      args.packageJsonPath ?? 'package.json',
      exec.signal,
    )
    packageJsonPath = manifest.path
    skipped = manifest.skipped
    for (const candidate of manifest.candidates) {
      for (const source of candidate.sources) addCandidate(candidateMap, candidate.request, source)
    }
  }

  const candidates = [...candidateMap.values()]
  if (candidates.length > MAX_PACKAGE_COUNT) {
    throw new DepCheckError(
      'DEP_CHECK_INPUT_INVALID',
      `dep_check accepts at most ${MAX_PACKAGE_COUNT} unique registry packages per call`,
    )
  }

  const audited = await auditInBatches(
    candidates.map(candidate => candidate.request),
    { ...options, signal: exec.signal },
  )
  const packages = audited.map((pkg, index) => canonicalPackage(
    pkg,
    candidates[index]?.sources ?? [{
      kind: 'argument',
      section: null,
      declaredName: pkg.requested.name,
    }],
    options,
  ))
  const summary = summarize(packages, skipped)

  return {
    schemaVersion: 1,
    verdict: summary.deny > 0 ? 'deny' : summary.ask > 0 ? 'ask' : 'allow',
    workspace,
    packageJsonPath,
    summary,
    packages,
    skipped,
  }
}

async function readManifestRequests(
  workspace: string,
  requestedPath: string,
  signal: AbortSignal,
): Promise<ManifestRequests> {
  if (requestedPath.trim() === '' || basename(requestedPath) !== 'package.json') {
    throw new DepCheckError(
      'DEP_CHECK_PATH_DENIED',
      'packageJsonPath must name a package.json inside the current workspace',
    )
  }

  const lexicalPath = resolve(workspace, requestedPath)
  if (!isPathInside(workspace, lexicalPath)) {
    throw new DepCheckError(
      'DEP_CHECK_PATH_DENIED',
      `packageJsonPath escapes the current workspace: ${requestedPath}`,
    )
  }

  throwIfAborted(signal)
  let realWorkspace: string
  let manifestPath: string
  try {
    [realWorkspace, manifestPath] = await Promise.all([
      realpath(workspace),
      realpath(lexicalPath),
    ])
  } catch (error: unknown) {
    throwIfAborted(signal)
    if (nodeErrorCode(error) === 'ENOENT') {
      throw new DepCheckError(
        'DEP_CHECK_MANIFEST_NOT_FOUND',
        `package.json not found: ${lexicalPath}`,
        { cause: error },
      )
    }
    throw new DepCheckError(
      'DEP_CHECK_MANIFEST_INVALID',
      `cannot resolve package.json: ${errorMessage(error)}`,
      { cause: error },
    )
  }
  if (!isPathInside(realWorkspace, manifestPath)) {
    throw new DepCheckError(
      'DEP_CHECK_PATH_DENIED',
      `packageJsonPath resolves outside the current workspace: ${requestedPath}`,
    )
  }

  throwIfAborted(signal)
  let metadata
  try {
    metadata = await stat(manifestPath)
  } catch (error: unknown) {
    throwIfAborted(signal)
    throw new DepCheckError(
      'DEP_CHECK_MANIFEST_INVALID',
      `cannot stat package.json: ${errorMessage(error)}`,
      { cause: error },
    )
  }
  if (!metadata.isFile()) {
    throw new DepCheckError('DEP_CHECK_MANIFEST_INVALID', `not a regular file: ${manifestPath}`)
  }
  if (metadata.size > MAX_PACKAGE_JSON_BYTES) {
    throw new DepCheckError(
      'DEP_CHECK_MANIFEST_TOO_LARGE',
      `package.json exceeds ${MAX_PACKAGE_JSON_BYTES} bytes: ${manifestPath}`,
    )
  }

  let text: string
  try {
    text = await readFile(manifestPath, { encoding: 'utf8', signal })
  } catch (error: unknown) {
    throwIfAborted(signal)
    throw new DepCheckError(
      'DEP_CHECK_MANIFEST_INVALID',
      `cannot read package.json: ${errorMessage(error)}`,
      { cause: error },
    )
  }
  throwIfAborted(signal)

  let document: unknown
  try {
    document = JSON.parse(text)
  } catch (error: unknown) {
    throw new DepCheckError(
      'DEP_CHECK_MANIFEST_INVALID',
      `package.json is not valid JSON: ${errorMessage(error)}`,
      { cause: error },
    )
  }
  if (!isRecord(document)) {
    throw new DepCheckError('DEP_CHECK_MANIFEST_INVALID', 'package.json root must be an object')
  }

  const candidates = new Map<string, Candidate>()
  const skipped: DepCheckSkipped[] = []
  for (const section of DEPENDENCY_SECTIONS) {
    const dependencies = document[section]
    if (dependencies === undefined) continue
    if (!isRecord(dependencies)) {
      throw new DepCheckError('DEP_CHECK_MANIFEST_INVALID', `package.json ${section} must be an object`)
    }
    for (const [name, value] of Object.entries(dependencies)) {
      if (typeof value !== 'string') {
        throw new DepCheckError(
          'DEP_CHECK_MANIFEST_INVALID',
          `package.json ${section}.${name} must be a string`,
        )
      }
      const source: DepCheckSource = { kind: 'dependency', section, declaredName: name }
      const request = parsePackageSpec(`${name}@${value}`)
      if (request === undefined) {
        skipped.push({
          name,
          requested: value,
          source,
          reason: isNonRegistrySpec(value) ? 'non-registry-spec' : 'invalid-package-spec',
        })
        continue
      }
      addCandidate(candidates, request, source)
    }
  }
  return { path: manifestPath, candidates: [...candidates.values()], skipped }
}

function addCandidate(
  candidates: Map<string, Candidate>,
  request: InstallRequest,
  source: DepCheckSource,
): void {
  const key = requestKey(request)
  const existing = candidates.get(key)
  if (existing === undefined) {
    candidates.set(key, { request, sources: [source] })
    return
  }
  if (!existing.sources.some(candidate => sourceKey(candidate) === sourceKey(source))) {
    existing.sources.push(source)
  }
}

async function auditInBatches(
  requests: readonly InstallRequest[],
  options: AuditOptions,
): Promise<PackageAudit[]> {
  const packages: PackageAudit[] = []
  for (let index = 0; index < requests.length; index += AUDIT_BATCH_SIZE) {
    throwIfAborted(options.signal)
    const report = await auditPackages(requests.slice(index, index + AUDIT_BATCH_SIZE), options)
    packages.push(...report.packages)
  }
  return packages
}

function canonicalPackage(
  pkg: PackageAudit,
  sources: DepCheckSource[],
  policy: AuditOptions,
): DepCheckPackage {
  return {
    name: pkg.requested.name,
    requested: pkg.requested.requested ?? null,
    resolvedVersion: pkg.resolved?.version ?? null,
    verdict: packageAuditVerdict(pkg, policy),
    degraded: pkg.errors.length > 0 || pkg.warnings.length > 0,
    whitelisted: pkg.whitelisted === true,
    sources,
    vulnerabilities: pkg.vulnerabilities.map(vulnerability => ({
      id: vulnerability.id,
      aliases: vulnerability.aliases,
      summary: vulnerability.summary,
      severity: vulnerability.severity,
      score: vulnerability.score ?? null,
    })),
    license: pkg.license === undefined
      ? null
      : {
          declared: pkg.license.license ?? null,
          status: pkg.license.status,
          blockedLicenses: pkg.license.blockedLicenses,
        },
    bundleSize: pkg.bundleSize === undefined
      ? null
      : {
          sizeBytes: pkg.bundleSize.size,
          gzipBytes: pkg.bundleSize.gzip,
          hasJsModule: pkg.bundleSize.hasJSModule,
          hasSideEffects: pkg.bundleSize.hasSideEffects,
          treeShakeable: pkg.bundleSize.treeShakeable,
        },
    health: pkg.health === undefined
      ? null
      : {
          weeklyDownloads: pkg.health.weeklyDownloads,
          ageDays: pkg.health.ageDays ?? null,
          maintainerCount: pkg.health.maintainerCount ?? null,
          similarPopularPackage: pkg.health.similarPopularPackage ?? null,
          issues: pkg.health.issues.map(issue => ({ ...issue })),
        },
    errors: pkg.errors.map(error => ({ ...error })),
    warnings: [...pkg.warnings],
    alternatives: alternativesFor(pkg.requested.name),
  }
}

function summarize(
  packages: readonly DepCheckPackage[],
  skipped: readonly DepCheckSkipped[],
): DepCheckResult['summary'] {
  return {
    total: packages.length,
    allow: packages.filter(pkg => pkg.verdict === 'allow').length,
    ask: packages.filter(pkg => pkg.verdict === 'ask').length,
    deny: packages.filter(pkg => pkg.verdict === 'deny').length,
    degraded: packages.filter(pkg => pkg.degraded).length,
    skipped: skipped.length,
  }
}

function requestKey(request: InstallRequest): string {
  return `${request.name}\0${request.requested ?? 'latest'}`
}

function sourceKey(source: DepCheckSource): string {
  return `${source.kind}\0${source.section ?? ''}\0${source.declaredName}`
}

function isPathInside(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate)
  return pathFromRoot === ''
    || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..' && !isAbsolute(pathFromRoot))
}

function isNonRegistrySpec(value: string): boolean {
  return /^(?:file|git|git\+(?:https?|ssh)|https?|link|workspace|github|gitlab|bitbucket):/i.test(value)
    || value.startsWith('.')
    || value.startsWith('/')
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted !== true) return
  throw signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted', 'AbortError')
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error.code === 'string' ? error.code : undefined
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
