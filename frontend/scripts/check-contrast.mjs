#!/usr/bin/env node
// Regression guard for text contrast on the dark surfaces.
//
// Greywatch's lowest-emphasis text token (--color-text-muted) is used on 10-12px
// labels, so it must clear WCAG AA (4.5:1) against the card and app backgrounds.
// This script parses the tokens straight from src/index.css and fails the build
// if a future token change reintroduces a low-contrast regression.
//
// Run with:  node scripts/check-contrast.mjs   (wired as `npm run check:contrast`)

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const css = readFileSync(resolve(here, '../src/styles/index.css'), 'utf8')

function token(name) {
  const m = css.match(new RegExp(`${name}\\s*:\\s*(#[0-9a-fA-F]{3,8})`))
  if (!m) throw new Error(`token ${name} not found in index.css`)
  return m[1]
}

function chan(c) {
  c /= 255
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}
function luminance(hex) {
  const h = hex.replace('#', '')
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16))
  return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)
}
function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

const AA_NORMAL = 4.5
const muted = token('--color-text-muted')
const secondary = token('--color-text-secondary')
const card = token('--color-card')
const background = token('--color-background')

const checks = [
  ['text-muted on card', muted, card],
  ['text-muted on background', muted, background],
  ['text-secondary on card', secondary, card],
]

let failed = false
for (const [label, fg, bg] of checks) {
  const r = ratio(fg, bg)
  const ok = r >= AA_NORMAL
  if (!ok) failed = true
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${r.toFixed(2)}:1  ${label}  (${fg} on ${bg})`)
}
if (failed) {
  console.error(`\nContrast regression: a text token fell below WCAG AA (${AA_NORMAL}:1).`)
  process.exit(1)
}
console.log('\nAll contrast checks pass.')
