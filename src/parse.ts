/**
 * A registry-backed package requested by an npm install command.
 *
 * Local paths, tarballs, git URLs and generic URLs are deliberately omitted:
 * OSV's npm query API cannot identify those inputs reliably.
 */
export interface InstallRequest {
  /** Canonical registry package name (aliases resolve to their target name). */
  name: string
  /** User-supplied version, range or dist-tag; absent means npm's default tag. */
  requested?: string
  /** Original package argument, retained for diagnostics. */
  raw: string
}

const INSTALL_SUBCOMMANDS = new Set(['install', 'i', 'add'])
const VALUE_OPTIONS = new Set([
  '--cache',
  '--include',
  '--install-strategy',
  '--loglevel',
  '--omit',
  '--prefix',
  '--registry',
  '--tag',
  '--userconfig',
  '--workspace',
  '-w',
])
const WRAPPERS = new Set(['command', 'env', 'sudo'])
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/
const PACKAGE_NAME = /^(?:@[A-Za-z0-9_.~-]+\/[A-Za-z0-9_.~-]+|[A-Za-z0-9_.~-]+)$/

/**
 * Parse every auditable npm package install in a shell command.
 *
 * The shell scanner understands quotes, escapes, `&&`, `||`, semicolons and
 * newlines. It intentionally does not expand variables, command substitutions,
 * aliases or shell functions: doing so without executing a shell would be both
 * inaccurate and unsafe.
 */
export function parseInstallCommand(command: string): InstallRequest[] {
  const installs: InstallRequest[] = []
  for (const segment of tokenizeShellSegments(command)) {
    installs.push(...parseSegment(segment))
  }
  return installs
}

function parseSegment(tokens: readonly string[]): InstallRequest[] {
  const npmIndex = findNpmInvocation(tokens)
  if (npmIndex === undefined) return []

  let index = npmIndex + 1
  while (index < tokens.length && !INSTALL_SUBCOMMANDS.has(tokens[index] ?? '') && tokens[index] !== 'ci') {
    index = skipOption(tokens, index)
  }
  if (tokens[index] === 'ci' || !INSTALL_SUBCOMMANDS.has(tokens[index] ?? '')) return []

  index += 1
  let defaultTag: string | undefined
  const packageTokens: string[] = []
  let optionsEnded = false

  while (index < tokens.length) {
    const token = tokens[index]
    if (token === undefined) break

    if (!optionsEnded && token === '--') {
      optionsEnded = true
      index += 1
      continue
    }

    if (!optionsEnded && token.startsWith('-')) {
      const tag = optionValue(tokens, index, '--tag')
      if (tag !== undefined) defaultTag = tag
      index = skipOption(tokens, index)
      continue
    }

    packageTokens.push(token)
    index += 1
  }

  return packageTokens.flatMap((raw) => {
    const parsed = parsePackageSpec(raw)
    if (parsed === undefined) return []
    if (parsed.requested === undefined && defaultTag !== undefined) {
      return [{ ...parsed, requested: defaultTag }]
    }
    return [parsed]
  })
}

function findNpmInvocation(tokens: readonly string[]): number | undefined {
  let index = 0
  while (index < tokens.length && ENV_ASSIGNMENT.test(tokens[index] ?? '')) index += 1

  if (WRAPPERS.has(tokens[index] ?? '')) {
    index += 1
    while (index < tokens.length) {
      const token = tokens[index] ?? ''
      if (ENV_ASSIGNMENT.test(token) || token.startsWith('-')) {
        index += 1
        continue
      }
      break
    }
  }

  const executable = tokens[index]?.replaceAll('\\', '/').split('/').at(-1)
  return executable === 'npm' || executable === 'npm.cmd' ? index : undefined
}

function skipOption(tokens: readonly string[], index: number): number {
  const token = tokens[index] ?? ''
  const optionName = token.split('=', 1)[0] ?? token
  if (!token.includes('=') && VALUE_OPTIONS.has(optionName)) return index + 2
  return index + 1
}

function optionValue(tokens: readonly string[], index: number, expected: string): string | undefined {
  const token = tokens[index] ?? ''
  if (token === expected) return tokens[index + 1]
  if (token.startsWith(`${expected}=`)) return token.slice(expected.length + 1)
  return undefined
}

export function parsePackageSpec(raw: string): InstallRequest | undefined {
  if (
    raw === '.'
    || raw === '..'
    || raw.startsWith('.')
    || raw.startsWith('/')
    || raw.startsWith('~')
    || /^(?:file|git|git\+(?:https?|ssh)|https?|link|workspace|github|gitlab|bitbucket):/i.test(raw)
  ) {
    return undefined
  }

  const splitAt = raw.startsWith('@')
    ? raw.indexOf('@', raw.indexOf('/') + 1)
    : raw.indexOf('@')
  const name = splitAt > 0 ? raw.slice(0, splitAt) : raw
  const requested = splitAt > 0 ? raw.slice(splitAt + 1) : undefined

  if (!PACKAGE_NAME.test(name)) return undefined

  if (requested?.startsWith('npm:')) {
    const aliased = parsePackageSpec(requested.slice(4))
    return aliased === undefined ? undefined : { ...aliased, raw }
  }
  if (/^(?:file|git|git\+(?:https?|ssh)|https?|link|workspace|github|gitlab|bitbucket):/i.test(requested ?? '')) return undefined

  return {
    name,
    ...(requested ? { requested } : {}),
    raw,
  }
}

/**
 * Tokenize only enough shell syntax to isolate command lists and arguments.
 * Operators inside quotes and escaped operators remain ordinary characters.
 */
function tokenizeShellSegments(command: string): string[][] {
  const segments: string[][] = []
  let segment: string[] = []
  let token = ''
  let quote: "'" | '"' | undefined

  const pushToken = (): void => {
    if (token.length === 0) return
    segment.push(token)
    token = ''
  }
  const pushSegment = (): void => {
    pushToken()
    if (segment.length > 0) segments.push(segment)
    segment = []
  }

  for (let index = 0; index < command.length; index += 1) {
    const char = command[index] ?? ''

    if (quote === "'") {
      if (char === "'") quote = undefined
      else token += char
      continue
    }

    if (char === '\\') {
      const next = command[index + 1]
      if (next !== undefined) {
        token += next
        index += 1
      } else {
        token += char
      }
      continue
    }

    if (quote === '"') {
      if (char === '"') quote = undefined
      else token += char
      continue
    }

    if (char === "'" || char === '"') {
      quote = char
      continue
    }

    if (/\s/.test(char)) {
      if (char === '\n' || char === '\r') pushSegment()
      else pushToken()
      continue
    }

    if (char === ';') {
      pushSegment()
      continue
    }

    if ((char === '&' && command[index + 1] === '&') || (char === '|' && command[index + 1] === '|')) {
      pushSegment()
      index += 1
      continue
    }

    token += char
  }

  pushSegment()
  return segments
}
