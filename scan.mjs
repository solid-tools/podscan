#!/usr/bin/env node
// podscan — scan your LAN for Solid pods + Nostr relays and write a
// hosts.jsonld "directory" into your pod's /private. An /etc/hosts for
// your pod: which machines are up, which run a Nostr relay (default :4444),
// and which verified WebID identities live behind them.
//
// The browser can't scan a LAN (no raw sockets), so this privileged step
// runs here and drops a same-origin, owner-only JSON-LD doc the pod's web
// apps can simply read. Run it on a schedule to keep the file warm.
//
// Usage:
//   podscan scan [--subnet 192.168.0.0/24] [--port 4444] [--pod-port 5444]
//                [--out ~/pod-data/private/net/hosts.jsonld] [--ttl-days 7]
//                [--timeout 5000] [--json]
//
// nmap is a system dependency (host discovery). `ws` is the only npm dep.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname } from 'node:path'
import { homedir } from 'node:os'
import WebSocket from 'ws'

// ---- args ----
const argv = process.argv.slice(2)
const cmd = argv[0] && !argv[0].startsWith('--') ? argv.shift() : 'scan'
const opt = (name, def) => { const i = argv.indexOf('--' + name); return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true) : def }
const flag = (name) => argv.includes('--' + name)
if (cmd !== 'scan') { console.error('usage: podscan scan [options] — see --help'); process.exit(2) }
if (flag('help')) { console.log(readFileSync(new URL('./README.md', import.meta.url), 'utf8')); process.exit(0) }

const PORT = Number(opt('port', 4444))
const POD_PORT = Number(opt('pod-port', 5444))
const TIMEOUT = Number(opt('timeout', 5000))
const TTL = Number(opt('ttl-days', 7)) * 86400e3
const OUT = String(opt('out', homedir() + '/pod-data/private/net/hosts.jsonld'))
const KIND0_LIMIT = 200
const arr = (v) => v == null ? [] : Array.isArray(v) ? v : [v]
const now = () => new Date().toISOString()

// ---- nostr key plumbing (matches the nostr app: hex is canonical) ----
const MB = 'fe70102' // multibase: 'f' base16 + e701 multicodec + 02 even-y
const hexFromMb = (mb) => (typeof mb === 'string' && mb.startsWith(MB) && mb.length === MB.length + 64) ? mb.slice(MB.length).toLowerCase() : null

// ---- LAN host discovery (nmap -sn, grepable; MACs from `ip neigh`) ----
function detectSubnet() {
  try {
    const dev = (execFileSync('ip', ['route', 'show', 'default'], { encoding: 'utf8' }).match(/dev\s+(\S+)/) || [])[1]
    const cidr = execFileSync('ip', ['-o', '-f', 'inet', 'addr', 'show', 'dev', dev], { encoding: 'utf8' }).match(/inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/)
    if (!cidr) return null
    const [, ip, bits] = cidr
    const o = ip.split('.').map(Number)
    if (Number(bits) === 24) return `${o[0]}.${o[1]}.${o[2]}.0/24`
    return `${ip}/${bits}` // nmap accepts host/bits; fine for /16 etc.
  } catch { return null }
}
function nmapHosts(subnet) {
  const out = execFileSync('nmap', ['-sn', '-oG', '-', subnet], { encoding: 'utf8', timeout: 120000 })
  const hosts = []
  for (const line of out.split('\n')) {
    const m = line.match(/^Host:\s+(\S+)\s+\(([^)]*)\)\s+Status:\s+Up/)
    if (m) hosts.push({ ip: m[1], hostname: m[2] || null })
  }
  return hosts
}
function macMap() {
  try {
    const out = execFileSync('ip', ['neigh'], { encoding: 'utf8' })
    const map = {}
    for (const l of out.split('\n')) { const m = l.match(/^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]+)/); if (m) map[m[1]] = m[2] }
    return map
  } catch { return {} }
}

// ---- relay probe + kind-0 query over WebSocket ----
function queryRelay(url) {
  return new Promise((resolve) => {
    const events = []; let up = false, done = false, ws
    const fin = () => { if (done) return; done = true; clearTimeout(t); try { ws && ws.close() } catch {} resolve({ up, events }) }
    const t = setTimeout(fin, TIMEOUT)
    try { ws = new WebSocket(url, { handshakeTimeout: TIMEOUT }) } catch { return resolve({ up: false, events: [] }) }
    ws.on('open', () => { up = true; ws.send(JSON.stringify(['REQ', 's', { kinds: [0], limit: KIND0_LIMIT }])) })
    ws.on('message', (d) => { try { const m = JSON.parse(d); if (m[0] === 'EVENT') events.push(m[2]); else if (m[0] === 'EOSE' || m[0] === 'CLOSED') fin() } catch {} })
    ws.on('error', fin)
    ws.on('close', fin)
  })
}

// newest kind-0 metadata per pubkey
function profilesFrom(events) {
  const map = {}
  for (const e of events) { if (!e || e.kind !== 0) continue; if (!map[e.pubkey] || e.created_at > map[e.pubkey]._ct) { try { const c = JSON.parse(e.content); c._ct = e.created_at; c.pubkey = e.pubkey; map[e.pubkey] = c } catch {} } }
  return Object.values(map)
}

function fetchT(url, headers) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), TIMEOUT)
  return fetch(url, { headers, signal: ctrl.signal }).finally(() => clearTimeout(t))
}

// Verify pubkey ⇄ WebID via the bidirectional card backlink (vm + authentication).
async function resolveWebID(pubkey, website, ip) {
  const cands = []
  if (website) { const b = website.endsWith('/') ? website : website + '/'; cands.push(website.includes('card.jsonld') ? website : b + 'profile/card.jsonld') }
  cands.push(`http://${ip}:${POD_PORT}/profile/card.jsonld`)
  for (const url of cands) {
    try {
      const r = await fetchT(url, { Accept: 'application/ld+json' })
      if (!r.ok) continue
      const doc = await r.json()
      const auth = arr(doc.authentication).map((a) => (a && a['@id']) || a)
      const ok = arr(doc.verificationMethod).some((vm) => hexFromMb(vm.publicKeyMultibase) === pubkey && auth.includes(vm['@id']))
      if (ok) return doc['@id'] || url
    } catch {}
  }
  return null
}

// ---- JSON-LD doc (an /etc/hosts for the pod) ----
const CONTEXT = {
  lan: 'urn:solid:lan#', schema: 'https://schema.org/',
  hosts: { '@id': 'lan:host', '@container': '@set' },
  services: { '@id': 'lan:service', '@container': '@set' },
  identities: { '@id': 'lan:identity', '@container': '@set' },
  webid: { '@id': 'lan:webid', '@type': '@id' },
  relay: 'lan:relay', ip: 'lan:ip', mac: 'lan:mac', hostname: 'lan:hostname',
  pubkey: 'lan:pubkey', name: 'schema:name', up: 'lan:up', verified: 'lan:verified',
  firstSeen: 'lan:firstSeen', lastSeen: 'lan:lastSeen', scannedAt: 'lan:scannedAt', subnet: 'lan:subnet'
}

async function main() {
  const subnet = String(opt('subnet', '') || detectSubnet() || '')
  if (!subnet) { console.error('Could not detect subnet — pass --subnet 192.168.0.0/24'); process.exit(1) }
  console.error(`podscan: scanning ${subnet} (relay :${PORT})…`)

  const up = nmapHosts(subnet)
  const macs = macMap()
  console.error(`  ${up.length} hosts up; probing relays…`)

  const stamp = now()
  const scanned = []
  for (const h of up) {
    const entry = { ip: h.ip, hostname: h.hostname, mac: macs[h.ip] || null, lastSeen: stamp }
    const { up: relayUp, events } = await queryRelay(`ws://${h.ip}:${PORT}`)
    if (relayUp) {
      entry.services = [{ '@type': 'lan:NostrRelay', relay: `ws://${h.ip}:${PORT}`, up: true }]
      const profiles = profilesFrom(events)
      const ids = []
      for (const pr of profiles) {
        const webid = await resolveWebID(pr.pubkey, pr.website, h.ip)
        ids.push({ pubkey: pr.pubkey, name: pr.name || pr.display_name || null, webid: webid || undefined, verified: !!webid })
      }
      if (ids.length) entry.identities = ids
      console.error(`  ✓ ${h.ip} relay up — ${ids.length} identities (${ids.filter((i) => i.verified).length} WebID-verified)`)
    }
    scanned.push(entry)
  }

  // merge with previous file (age out hosts unseen beyond TTL)
  let prev = null
  if (existsSync(OUT)) { try { prev = JSON.parse(readFileSync(OUT, 'utf8')) } catch {} }
  const byIp = {}
  for (const h of arr(prev && prev.hosts)) byIp[h.ip] = h
  const cutoff = Date.now() - TTL
  for (const h of scanned) { h.firstSeen = (byIp[h.ip] && byIp[h.ip].firstSeen) || stamp; byIp[h.ip] = h }
  const merged = Object.values(byIp).filter((h) => new Date(h.lastSeen).getTime() >= cutoff)
    .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))

  const doc = { '@context': CONTEXT, '@id': '#lan', '@type': 'lan:LocalNetwork', subnet, scannedAt: stamp, hosts: merged }
  const json = JSON.stringify(doc, null, 2)

  if (flag('json')) { console.log(json); return }
  mkdirSync(dirname(OUT), { recursive: true })
  writeFileSync(OUT, json)
  const relays = merged.filter((h) => h.services).length
  const ids = merged.reduce((n, h) => n + arr(h.identities).length, 0)
  console.error(`podscan: wrote ${OUT} — ${merged.length} hosts, ${relays} relays, ${ids} identities`)
}

main().catch((e) => { console.error('podscan error:', e.message || e); process.exit(1) })
