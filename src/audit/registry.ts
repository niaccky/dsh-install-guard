import { maxSatisfying, valid } from 'semver'
import type { InstallRequest } from '../parse.js'
import { loadCached, METADATA_TTL_MS, type TtlCache } from '../cache.js'

const DEFAULT_REGISTRY_URL = 'https://registry.npmjs.org'

export interface PackageMetadata {
  license?: string
  createdAt?: string
  maintainers?: number
  deprecated?: string
}

export interface ResolvedPackage extends InstallRequest {
  version: string
  metadata: PackageMetadata
}

export interface RegistryOptions {
  fetch?: typeof globalThis.fetch
  registryUrl?: string
  signal?: AbortSignal
  cache?: TtlCache
  metadataTtlMs?: number
  onCacheFallback?: (message: string) => void
}

interface Packument {
  'dist-tags'?: Record<string, unknown>
  versions?: Record<string, unknown>
  license?: unknown
  time?: unknown
  maintainers?: unknown
}

/** Resolve npm's range/tag/default selection to one exact published version. */
export async function resolvePackageVersion(
  request: InstallRequest,
  options: RegistryOptions = {},
): Promise<ResolvedPackage> {
  throwIfAborted(options.signal)
  const fetchImpl = options.fetch ?? globalThis.fetch
  const registryUrl = (options.registryUrl ?? DEFAULT_REGISTRY_URL).replace(/\/+$/, '')
  const url = `${registryUrl}/${encodeURIComponent(request.name)}`
  const packument = await loadCached({
    cache: options.cache,
    key: `registry:${url}`,
    ttlMs: options.metadataTtlMs ?? METADATA_TTL_MS,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    staleMessage: `npm registry 缓存已过期，离线沿用 ${request.name} 的旧元数据`,
    ...(options.onCacheFallback === undefined ? {} : { onStale: options.onCacheFallback }),
    load: async () => {
      const response = await fetchImpl(url, {
        // License, creation time and maintainer data are not guaranteed in
        // npm's abbreviated install-v1 document, so request the full packument.
        headers: { accept: 'application/json' },
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      })
      if (!response.ok) {
        throw new Error(`npm registry returned ${response.status} for ${request.name}`)
      }

      const body: unknown = await response.json()
      if (!isRecord(body)) throw new Error(`npm registry returned an invalid document for ${request.name}`)
      if (!isRecord(body.versions) || Object.keys(body.versions).length === 0) {
        throw new Error(`npm registry returned no versions for ${request.name}`)
      }
      return body as Packument
    },
  })
  const versions = isRecord(packument.versions) ? Object.keys(packument.versions) : []

  const exactVersion = selectVersion(request, packument, versions)
  if (exactVersion === undefined || !versions.includes(exactVersion)) {
    const requested = request.requested ?? 'latest'
    throw new Error(`npm registry could not resolve ${request.name}@${requested}`)
  }

  const versionDocument = isRecord(packument.versions?.[exactVersion])
    ? packument.versions[exactVersion]
    : {}
  return {
    ...request,
    version: exactVersion,
    metadata: packageMetadata(packument, versionDocument),
  }
}

function selectVersion(
  request: InstallRequest,
  packument: Packument,
  versions: readonly string[],
): string | undefined {
  const requested = request.requested ?? 'latest'
  const tags = isRecord(packument['dist-tags']) ? packument['dist-tags'] : {}
  const taggedVersion = tags[requested]
  if (typeof taggedVersion === 'string') return taggedVersion

  const exact = valid(requested)
  if (exact !== null) return exact

  try {
    return maxSatisfying(versions, requested, { includePrerelease: false }) ?? undefined
  } catch {
    return undefined
  }
}

function packageMetadata(
  packument: Packument,
  versionDocument: Record<string, unknown>,
): PackageMetadata {
  const license = licenseText(versionDocument.license) ?? licenseText(packument.license)
  const time = isRecord(packument.time) ? packument.time : {}
  const createdAt = typeof time.created === 'string' ? time.created : undefined
  const maintainers = Array.isArray(packument.maintainers)
    ? packument.maintainers.length
    : Array.isArray(versionDocument.maintainers)
      ? versionDocument.maintainers.length
      : undefined
  const deprecated = typeof versionDocument.deprecated === 'string' && versionDocument.deprecated.trim() !== ''
    ? versionDocument.deprecated
    : undefined
  return {
    ...(license === undefined ? {} : { license }),
    ...(createdAt === undefined ? {} : { createdAt }),
    ...(maintainers === undefined ? {} : { maintainers }),
    ...(deprecated === undefined ? {} : { deprecated }),
  }
}

function licenseText(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim() !== '') return value.trim()
  if (isRecord(value) && typeof value.type === 'string' && value.type.trim() !== '') {
    return value.type.trim()
  }
  if (Array.isArray(value)) {
    const licenses = value.map(licenseText).filter((item): item is string => item !== undefined)
    return licenses.length === 0 ? undefined : licenses.join(' OR ')
  }
  return undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted !== true) return
  throw signal.reason instanceof Error ? signal.reason : new DOMException('The operation was aborted', 'AbortError')
}
