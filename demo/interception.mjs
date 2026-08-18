#!/usr/bin/env node

import { apply } from '../lib/index.js'

const command = 'npm install lodash@4.17.20'
let handler
let registeredTool
let reachedExecutor = false

const context = {
  logger: {
    warn(message) {
      console.warn(`[guard warning] ${message}`)
    },
  },
  tools: {
    register(tool) {
      registeredTool = tool
      return () => undefined
    },
  },
  on(event, candidate) {
    if (event === 'tools/pre-execute') handler = candidate
    return () => undefined
  },
}

apply(context)

if (registeredTool?.name !== 'dep_check' || typeof handler !== 'function') {
  throw new Error('plugin did not register the expected guard and dep_check tool')
}

const originalFetch = globalThis.fetch
globalThis.fetch = demoFetch

try {
  console.log(`$ ${command}`)
  console.log('[guard] intercepted before command execution')

  const decision = await handler({
    name: 'bash',
    arguments: { command },
    signal: new AbortController().signal,
  }, async () => {
    reachedExecutor = true
    return { kind: 'allow' }
  })

  console.log(`\nDecision: ${decision.kind.toUpperCase()}`)
  if ('reason' in decision) console.log(decision.reason)
  console.log(`\nInstall executor reached: ${reachedExecutor ? 'yes' : 'no'}`)

  if (decision.kind !== 'deny' || reachedExecutor) {
    throw new Error('demo invariant failed: the vulnerable install was not denied')
  }
} finally {
  globalThis.fetch = originalFetch
}

async function demoFetch(input) {
  const url = String(input)

  if (url.includes('registry.npmjs.org')) {
    return jsonResponse({
      'dist-tags': { latest: '4.17.21' },
      versions: {
        '4.17.20': { license: 'MIT' },
        '4.17.21': { license: 'MIT' },
      },
      time: { created: '2012-04-23T00:00:00.000Z' },
      maintainers: [{ name: 'demo-maintainer' }],
    })
  }

  if (url.includes('api.osv.dev')) {
    return jsonResponse({
      vulns: [{
        id: 'GHSA-35jh-r3h4-6jhm',
        aliases: ['CVE-2021-23337'],
        summary: 'Command Injection in lodash',
        database_specific: { severity: 'HIGH' },
      }],
    })
  }

  if (url.includes('bundlephobia.com')) {
    return jsonResponse({
      size: 25_000,
      gzip: 7_000,
      hasJSModule: true,
      hasSideEffects: false,
    })
  }

  if (url.includes('api.npmjs.org/downloads')) {
    return jsonResponse({ downloads: 50_000_000 })
  }

  return new Response('unexpected demo endpoint', { status: 500 })
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
