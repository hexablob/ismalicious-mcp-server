#!/usr/bin/env node
/**
 * Validate server.json against the schema it declares in `$schema`.
 *
 * `ajv` and `ajv-formats` are not dependencies of this zero-dependency
 * package; the caller installs them somewhere and points AJV_PREFIX at it:
 *
 *   npm install --no-save --prefix /tmp/ajv ajv@8 ajv-formats@3
 *   AJV_PREFIX=/tmp/ajv node scripts/validate-server-json.mjs
 *
 * The registry's 2025-12-11 schema is draft-07 with `format` keywords, hence
 * ajv-formats and `strict: false` (the schema uses vocabulary Ajv's strict
 * mode rejects).
 */
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const prefix = process.env.AJV_PREFIX
if (!prefix) {
  console.error('validate-server-json: set AJV_PREFIX to a directory holding node_modules/ajv and ajv-formats')
  process.exit(2)
}
const require = createRequire(join(prefix, 'node_modules', 'x.js'))
const Ajv = require('ajv')
const addFormats = require('ajv-formats')

const server = JSON.parse(readFileSync(join(here, '..', 'server.json'), 'utf8'))
const schemaUrl = server.$schema
if (!schemaUrl) {
  console.error('validate-server-json: server.json has no $schema')
  process.exit(1)
}
const res = await fetch(schemaUrl)
if (!res.ok) {
  console.error(`validate-server-json: could not fetch ${schemaUrl} (${res.status})`)
  process.exit(1)
}
const schema = await res.json()

const ajv = new Ajv({ strict: false, allErrors: true })
addFormats(ajv)
const validate = ajv.compile(schema)
if (!validate(server)) {
  for (const err of validate.errors ?? []) {
    console.error(`validate-server-json: ${err.instancePath || '/'} ${err.message}`)
  }
  process.exit(1)
}
console.log(`validate-server-json: ok (${schemaUrl})`)
