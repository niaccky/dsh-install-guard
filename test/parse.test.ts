import { describe, expect, it } from 'vitest'
import { parseInstallCommand } from '../src/parse.js'

describe('parseInstallCommand', () => {
  it('parses flags, ranges, scoped names and multiple packages', () => {
    expect(parseInstallCommand('npm i -D lodash@^4.17.0 @scope/name@~2.3.0 react')).toEqual([
      { name: 'lodash', requested: '^4.17.0', raw: 'lodash@^4.17.0' },
      { name: '@scope/name', requested: '~2.3.0', raw: '@scope/name@~2.3.0' },
      { name: 'react', raw: 'react' },
    ])
  })

  it('finds npm installs in compound commands but respects quoting and escapes', () => {
    const command = [
      'cd packages/app && npm add "left-pad@1.3.0"',
      'echo "npm i ignored; still ignored"',
      String.raw`npm install semi\;colon || npm i zod@latest`,
    ].join('; ')

    expect(parseInstallCommand(command)).toEqual([
      { name: 'left-pad', requested: '1.3.0', raw: 'left-pad@1.3.0' },
      { name: 'zod', requested: 'latest', raw: 'zod@latest' },
    ])
  })

  it('allows lockfile-only and unrelated npm commands', () => {
    expect(parseInstallCommand('npm install && npm ci; npm test')).toEqual([])
  })

  it('skips option values and applies an explicit default tag', () => {
    expect(parseInstallCommand(
      'npm --prefix packages/app install --registry https://registry.npmjs.org --tag next foo -w app bar@1',
    )).toEqual([
      { name: 'foo', requested: 'next', raw: 'foo' },
      { name: 'bar', requested: '1', raw: 'bar@1' },
    ])
  })

  it('ignores local and source-control specs while keeping registry aliases', () => {
    expect(parseInstallCommand(
      'npm i . ../shared file:./pkg local@file:./pkg source@git+https://example.test/repo https://example.test/pkg.tgz git+https://example.test/repo alias@npm:real-package@2',
    )).toEqual([
      { name: 'real-package', requested: '2', raw: 'alias@npm:real-package@2' },
    ])
  })

  it('supports environment prefixes, executable paths and the option terminator', () => {
    expect(parseInstallCommand('NODE_ENV=dev /usr/local/bin/npm i -- -odd-name')).toEqual([
      { name: '-odd-name', raw: '-odd-name' },
    ])
  })
})
