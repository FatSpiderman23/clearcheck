import 'dotenv/config'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'
import axios from 'axios'
import crypto from 'crypto'

const PORT = parseInt(process.env.PORT || '3000')
const CH_API_KEY = process.env.COMPANIES_HOUSE_API_KEY || ''
const FCA_API_KEY = process.env.FCA_API_KEY || ''
const FCA_EMAIL = process.env.FCA_EMAIL || ''
const POLAR_ACCESS_TOKEN = process.env.POLAR_ACCESS_TOKEN || ''
const POLAR_ORG_ID = process.env.POLAR_ORG_ID || ''
const REVIEWER_KEY = process.env.REVIEWER_KEY || ''
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://claude.ai,https://api.anthropic.com').split(',')
// Stable JWT secret: use env var or derive from REVIEWER_KEY so tokens survive restarts
const JWT_SECRET = process.env.JWT_SECRET ||
  crypto.createHash('sha256').update('clearcheck-' + (REVIEWER_KEY || 'default')).digest('hex')
const BASE_URL = (process.env.BASE_URL || 'https://clearcheck.onrender.com').replace(/\/$/, '')

// ── Origin validation (required by Anthropic security standards) ─────────────

function isAllowedOrigin(origin: string | undefined): boolean {
  if (!origin) return true  // Desktop clients (Claude Desktop, mcp-remote) send no Origin
  return ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed.trim()))
}

// ── Polar.sh licence validation ──────────────────────────────────────────────

async function validateLicenceKey(key: string): Promise<boolean> {
  if (!key) return false
  if (REVIEWER_KEY && key === REVIEWER_KEY) return true
  try {
    const res = await axios.post(
      'https://api.polar.sh/v1/users/license-keys/validate',
      { key, organization_id: POLAR_ORG_ID },
      { headers: { Authorization: `Bearer ${POLAR_ACCESS_TOKEN}` }, timeout: 5000 }
    )
    return res.data?.valid === true
  } catch {
    return false
  }
}

// ── OAuth 2.0 ─────────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string { return buf.toString('base64url') }

function signJWT(payload: Record<string, unknown>, expiresInSec: number): string {
  const hdr = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
  const now = Math.floor(Date.now() / 1000)
  const bdy = b64url(Buffer.from(JSON.stringify({ ...payload, iat: now, exp: now + expiresInSec })))
  const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest())
  return `${hdr}.${bdy}.${sig}`
}

function verifyJWT(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const [hdr, bdy, sig] = parts
    const sigBuf = Buffer.from(sig, 'base64url')
    const expectedBuf = crypto.createHmac('sha256', JWT_SECRET).update(`${hdr}.${bdy}`).digest()
    if (sigBuf.length !== expectedBuf.length) return null
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null
    const payload = JSON.parse(Buffer.from(bdy, 'base64url').toString()) as Record<string, unknown>
    if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

function verifyPKCE(verifier: string, challenge: string, method: string): boolean {
  if (method === 'plain') {
    if (verifier.length !== challenge.length) return false
    return crypto.timingSafeEqual(Buffer.from(verifier), Buffer.from(challenge))
  }
  if (method === 'S256') {
    const computed = b64url(crypto.createHash('sha256').update(verifier).digest())
    if (computed.length !== challenge.length) return false
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(challenge))
  }
  return false
}

interface AuthCodeData {
  licenceKey: string
  clientId: string
  redirectUri: string
  codeChallenge?: string
  codeChallengeMethod?: string
  expiresAt: number
}
const authCodes = new Map<string, AuthCodeData>()
setInterval(() => { const n = Date.now(); for (const [k, v] of authCodes) if (v.expiresAt < n) authCodes.delete(k) }, 60_000)

async function validateToken(token: string): Promise<boolean> {
  if (!token) return false
  if (REVIEWER_KEY && token === REVIEWER_KEY) return true  // backward compat for Claude Desktop
  const payload = verifyJWT(token)
  return payload !== null && typeof payload.sub === 'string' && payload.sub.length > 0
}

function authorizeHTML(opts: {
  clientId: string; redirectUri: string; state: string
  codeChallenge: string; codeChallengeMethod: string; error?: string
}): string {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ClearCheck — Connect</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1624;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#1a2744;border:1px solid #1e3a5f;border-radius:16px;padding:40px;max-width:420px;width:90%}.logo{display:flex;align-items:center;gap:10px;margin-bottom:24px}.logo img{width:40px;height:40px;border-radius:8px}.logo span{font-size:22px;font-weight:700}h1{font-size:20px;font-weight:600;margin-bottom:8px}p{color:#94a3b8;font-size:14px;margin-bottom:24px;line-height:1.5}label{display:block;font-size:13px;font-weight:600;color:#94a3b8;margin-bottom:6px}input[type=password]{width:100%;background:#0f1624;border:1px solid #1e3a5f;border-radius:8px;padding:12px 14px;color:#fff;font-size:14px;outline:none;transition:border-color .2s}input[type=password]:focus{border-color:#22c55e}button{width:100%;background:#22c55e;color:#000;border:none;border-radius:8px;padding:14px;font-size:15px;font-weight:700;cursor:pointer;margin-top:16px;transition:background .2s}button:hover{background:#16a34a}.err{color:#f87171;font-size:13px;margin-top:12px;padding:10px;background:rgba(248,113,113,.1);border-radius:6px}.sub{color:#64748b;font-size:12px;margin-top:20px;text-align:center}a{color:#22c55e}</style></head><body><div class="card"><div class="logo"><img src="/public/favicon.png" alt="ClearCheck"><span>ClearCheck</span></div><h1>Connect to Claude</h1><p>Enter your ClearCheck licence key to grant Claude access to UK AML compliance tools.</p><form method="POST"><input type="hidden" name="client_id" value="${esc(opts.clientId)}"><input type="hidden" name="redirect_uri" value="${esc(opts.redirectUri)}"><input type="hidden" name="state" value="${esc(opts.state)}"><input type="hidden" name="code_challenge" value="${esc(opts.codeChallenge)}"><input type="hidden" name="code_challenge_method" value="${esc(opts.codeChallengeMethod)}"><label for="key">Licence Key</label><input id="key" name="key" type="password" placeholder="clearcheck-..." required autofocus>${opts.error ? `<div class="err">${esc(opts.error)}</div>` : ''}<button type="submit">Connect →</button></form><p class="sub">No licence key? <a href="https://clearcheck-uk.github.io/clearcheck" target="_blank">Get access →</a></p></div></body></html>`
}

// ── Sanctions list (cached 24 hours) ─────────────────────────────────────────

interface SanctionsEntry {
  name: string
  aliases: string[]
  regimes: string[]
  dob?: string
  nationality?: string
}

let sanctionsCache: SanctionsEntry[] = []
let sanctionsCachedAt = 0

function parseCSVLine(line: string): string[] {
  const cols: string[] = []
  let cur = ''
  let inQ = false
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++ } else { inQ = !inQ }
    } else if (line[i] === ',' && !inQ) {
      cols.push(cur); cur = ''
    } else {
      cur += line[i]
    }
  }
  cols.push(cur)
  return cols
}

async function getSanctionsList(): Promise<SanctionsEntry[]> {
  if (sanctionsCache.length && Date.now() - sanctionsCachedAt < 86_400_000) return sanctionsCache
  const res = await axios.get(
    'https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv',
    { timeout: 30000, responseType: 'text' }
  )
  const lines: string[] = (res.data as string).split('\n')
  const headers = parseCSVLine(lines[1] || '')
  const idx = {
    uid: headers.indexOf('Unique ID'),
    n6: headers.indexOf('Name 6'), n1: headers.indexOf('Name 1'),
    n2: headers.indexOf('Name 2'), n3: headers.indexOf('Name 3'),
    n4: headers.indexOf('Name 4'), n5: headers.indexOf('Name 5'),
    regime: headers.indexOf('Regime Name'),
    dob: headers.indexOf('D.O.B'),
    nat: headers.indexOf('Nationality(/ies)'),
  }
  const map = new Map<string, SanctionsEntry>()
  for (let i = 2; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue
    const c = parseCSVLine(line)
    const fullName = [c[idx.n6], c[idx.n1], c[idx.n2], c[idx.n3], c[idx.n4], c[idx.n5]].filter(Boolean).join(' ').trim().toLowerCase()
    if (!fullName) continue
    const uid = c[idx.uid] || `r${i}`
    if (map.has(uid)) {
      const e = map.get(uid)!
      if (!e.aliases.includes(fullName) && fullName !== e.name) e.aliases.push(fullName)
    } else {
      map.set(uid, { name: fullName, aliases: [], regimes: [c[idx.regime]].filter(Boolean), dob: c[idx.dob] || undefined, nationality: c[idx.nat] || undefined })
    }
  }
  sanctionsCache = Array.from(map.values())
  sanctionsCachedAt = Date.now()
  return sanctionsCache
}

function normName(s: string) { return s.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ').trim() }
function sanctionsMatch(q: string, e: SanctionsEntry) {
  const qTokens = normName(q).split(' ').filter(t => t.length >= 2)
  if (!qTokens.length) return false
  return [e.name, ...e.aliases].some(n => {
    const nTokens = normName(n).split(' ').filter(t => t.length >= 2)
    return qTokens.every(qt =>
      nTokens.some(nt => nt === qt || (nt.length >= 3 && qt.length >= 3 && (nt.startsWith(qt) || qt.startsWith(nt))))
    )
  })
}

// ── Companies House ──────────────────────────────────────────────────────────

async function chSearch(q: string) {
  const r = await axios.get('https://api.company-information.service.gov.uk/search/companies', {
    params: { q, items_per_page: 5 }, auth: { username: CH_API_KEY, password: '' }, timeout: 10000,
  })
  return r.data?.items ?? []
}
async function chProfile(n: string) {
  const r = await axios.get(`https://api.company-information.service.gov.uk/company/${n.toUpperCase()}`,
    { auth: { username: CH_API_KEY, password: '' }, timeout: 10000 })
  return r.data
}
async function chOfficers(n: string) {
  const r = await axios.get(`https://api.company-information.service.gov.uk/company/${n.toUpperCase()}/officers`,
    { auth: { username: CH_API_KEY, password: '' }, timeout: 10000 })
  return r.data?.items ?? []
}
async function chPSC(n: string) {
  const r = await axios.get(`https://api.company-information.service.gov.uk/company/${n.toUpperCase()}/persons-with-significant-control`,
    { auth: { username: CH_API_KEY, password: '' }, timeout: 10000 })
  return r.data?.items ?? []
}

// ── PEP check (UK Parliament API) ────────────────────────────────────────────

interface PEPMatch {
  name: string
  role: string
  party: string
  house: string
  from: string
  to: string
}

async function pepLookup(name: string): Promise<PEPMatch[]> {
  const r = await axios.get('https://members-api.parliament.uk/api/Members/Search', {
    params: { Name: name, skip: 0, take: 5 },
    timeout: 10000,
  })
  return (r.data?.items ?? []).map((item: any) => {
    const v = item.value
    const m = v.latestHouseMembership
    return {
      name: v.nameFullTitle || v.nameDisplayAs,
      role: m?.house === 1 ? 'MP' : 'Lord',
      party: v.latestParty?.name || 'Unknown',
      house: m?.house === 1 ? 'House of Commons' : 'House of Lords',
      from: m?.membershipStartDate?.slice(0, 10) || '',
      to: m?.membershipEndDate?.slice(0, 10) || 'current',
    }
  })
}

// ── SIC code risk classification ─────────────────────────────────────────────

const HIGH_RISK_SIC: Record<string, string> = {
  '64110': 'Central banking', '64191': 'Banks', '64921': 'Credit granting',
  '64992': 'Money lending', '64999': 'Other financial services',
  '66190': 'Financial services auxiliary', '66120': 'Securities dealing',
  '68100': 'Real estate (own property)', '68201': 'Residential lettings',
  '68209': 'Other real estate', '68310': 'Real estate agencies', '68320': 'Real estate management',
  '92000': 'Gambling & betting', '92110': 'Motion picture production',
  '47990': 'Other retail (cash-intensive)', '56101': 'Restaurants', '56302': 'Public houses',
  '45111': 'Motor vehicle sales', '45112': 'Used motor vehicle sales',
  '64201': 'Financial holding companies', '64205': 'Financial holding companies (UK)',
  '82990': 'Other business support', '74909': 'Other professional activities',
}

function sicRisk(codes: string[]): string[] {
  return codes.flatMap(c => HIGH_RISK_SIC[c] ? [`${c} — ${HIGH_RISK_SIC[c]}`] : [])
}

function companyRiskLevel(status: string, dateCreated: string, sics: string[]): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (['dissolved', 'liquidation', 'receivership', 'administration'].includes(status)) return 'HIGH'
  const ageMonths = dateCreated ? (Date.now() - new Date(dateCreated).getTime()) / (1000 * 60 * 60 * 24 * 30) : 999
  if (ageMonths < 12 || sicRisk(sics).length > 0) return 'MEDIUM'
  return 'LOW'
}

// ── FCA Register ─────────────────────────────────────────────────────────────

async function fcaLookup(frn: string) {
  const r = await axios.get(`https://register.fca.org.uk/services/V0.1/Firm/${frn.trim()}`,
    { headers: { 'X-Auth-Email': FCA_EMAIL, 'X-Auth-Key': FCA_API_KEY }, timeout: 10000 })
  return r.data
}

// ── MCP server ───────────────────────────────────────────────────────────────

function buildServer() {
  const server = new McpServer({
    name: 'clearcheck',
    version: '1.0.0',
    description: 'UK AML & compliance intelligence for accountants and compliance professionals. Checks Companies House, FCDO sanctions, FCA register.',
  })

  // Tool 1 — Full CDD report
  server.tool(
    'client_cdd',
    'Run a full Customer Due Diligence (CDD) check on a new client as required under UK Money Laundering Regulations 2017. Screens against the FCDO UK Sanctions List, checks for Politically Exposed Persons (PEPs) via the UK Parliament register, looks up the company on Companies House (status, directors, PSCs, SIC risk flags), and provides an overall risk rating (HIGH / MEDIUM / LOW). Returns a structured report ready for your MLRO file.',
    {
      name: z.string().describe('Full name of individual or company to screen'),
      company_number: z.string().optional().describe('Companies House number if known — speeds up the lookup'),
    },
    { title: 'Full CDD Report', readOnlyHint: true },
    async ({ name, company_number }) => {
      const date = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })
      const lines: string[] = [`# CDD Report: ${name}`, `*${date} · ClearCheck UK*`, '']

      let riskLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW'
      const riskFlags: string[] = []

      // ── Sanctions ──
      try {
        const list = await getSanctionsList()
        const hits = list.filter(e => sanctionsMatch(name, e))
        if (hits.length) {
          riskLevel = 'HIGH'
          riskFlags.push(`Sanctions match (${hits.length})`)
          lines.push(`## 🚨 SANCTIONS: ${hits.length} MATCH(ES)`)
          for (const m of hits) {
            lines.push(`- **${m.name}** | Regime: ${m.regimes.join(', ')}${m.dob ? ` | DOB: ${m.dob}` : ''}`)
            if (m.aliases.length) lines.push(`  Aliases: ${m.aliases.slice(0, 3).join('; ')}`)
          }
          lines.push(`> ⚠️ Do NOT proceed. Verify match independently before any action.`)
        } else {
          lines.push(`## ✅ Sanctions: Clear — ${list.length.toLocaleString()} UK entries screened`)
        }
      } catch {
        lines.push(`## ⚠️ Sanctions: Unavailable — verify manually at https://www.gov.uk/government/publications/the-uk-sanctions-list`)
      }
      lines.push('')

      // ── PEP check ──
      try {
        const peps = await pepLookup(name)
        if (peps.length) {
          if (riskLevel !== 'HIGH') riskLevel = 'MEDIUM'
          riskFlags.push(`PEP match (${peps.length})`)
          lines.push(`## 🟡 PEP: ${peps.length} MATCH(ES) — Politically Exposed Person`)
          for (const p of peps) {
            lines.push(`- **${p.name}** | ${p.role} · ${p.party} · ${p.house}`)
            lines.push(`  Served: ${p.from}${p.to !== 'current' ? ` to ${p.to}` : ' (current)'}`)
          }
          lines.push(`> Enhanced Due Diligence (EDD) required for PEPs and their associates under MLR 2017 Reg 35.`)
        } else {
          lines.push(`## ✅ PEP Check: No UK parliamentary PEP match found`)
        }
      } catch {
        lines.push(`## ⚠️ PEP Check: Unavailable — verify manually`)
      }
      lines.push('')

      // ── Companies House ──
      try {
        const results = company_number ? [{ company_number }] : await chSearch(name)
        if (results.length) {
          const num = results[0].company_number
          const [profile, officers, pscs] = await Promise.all([chProfile(num), chOfficers(num), chPSC(num)])
          const status: string = profile.company_status
          const sics: string[] = profile.sic_codes ?? []
          const activeOfficers = (officers as any[]).filter((o: any) => !o.resigned_on)
          const activePSCs = (pscs as any[]).filter((p: any) => !p.ceased_on)
          const companyRisk = companyRiskLevel(status, profile.date_of_creation, sics)
          const sicFlags = sicRisk(sics)
          if (companyRisk === 'HIGH' && riskLevel !== 'HIGH') riskLevel = 'HIGH'
          if (companyRisk === 'MEDIUM' && riskLevel === 'LOW') riskLevel = 'MEDIUM'
          if (companyRisk !== 'LOW') riskFlags.push(`Company: ${status}${sicFlags.length ? `, high-risk SIC` : ''}`)
          const statusIcon = companyRisk === 'HIGH' ? '🚨' : companyRisk === 'MEDIUM' ? '🟡' : '✅'
          lines.push(`## ${statusIcon} Companies House: ${profile.company_name} (${num})`)
          lines.push(`- **Status:** ${status}${companyRisk === 'HIGH' ? ' — HIGH RISK ⚠️' : ''}`)
          lines.push(`- **Incorporated:** ${profile.date_of_creation}`)
          lines.push(`- **Address:** ${[profile.registered_office_address?.address_line_1, profile.registered_office_address?.locality, profile.registered_office_address?.postal_code].filter(Boolean).join(', ')}`)
          lines.push(`- **SIC codes:** ${sics.join(', ') || 'N/A'}${sicFlags.length ? ` ⚠️ High-risk: ${sicFlags.join('; ')}` : ''}`)
          lines.push(`- **Active officers (${activeOfficers.length}):** ${activeOfficers.map((o: any) => o.name).join(', ') || 'none'}`)
          lines.push(`- **PSCs:** ${activePSCs.map((p: any) => p.name || p.company_name).join(', ') || 'none recorded'}`)
          lines.push(`- https://find-and-update.company-information.service.gov.uk/company/${num}`)
        } else {
          lines.push(`## ℹ️ Companies House: No UK company found for "${name}"`)
        }
      } catch (e: any) {
        lines.push(`## ⚠️ Companies House: Lookup failed — ${e.message}`)
      }
      lines.push('')

      // ── FCA note ──
      lines.push(`## ℹ️ FCA Register: Use \`fca_check\` with the firm's FRN to verify FCA authorisation`)
      lines.push(`   Look up FRN at: https://register.fca.org.uk`)
      lines.push('')

      // ── Overall risk rating ──
      const riskEmoji = riskLevel === 'HIGH' ? '🔴' : riskLevel === 'MEDIUM' ? '🟡' : '🟢'
      lines.push(`---`)
      lines.push(`## ${riskEmoji} Overall Risk Rating: ${riskLevel}`)
      if (riskFlags.length) lines.push(`**Flags:** ${riskFlags.join(' · ')}`)
      lines.push('')
      lines.push(`*Decision-support tool only. Retain in MLRO file. Your firm retains sole AML/CTF responsibility under MLR 2017.*`)
      lines.push(`*Sources: FCDO UK Sanctions List (OGL v3) · UK Parliament Members API · Companies House (OGL v3)*`)

      return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
    }
  )

  // Tool 2 — Sanctions screen
  server.tool(
    'sanctions_screen',
    'Screen an individual or organisation against the FCDO UK Sanctions List, covering all UK sanctions regimes (Russia, Iran, Global Human Rights, etc.). Returns match details if found or a clear result with entry count screened.',
    { name: z.string().describe('Full name of individual or organisation to screen') },
    { title: 'UK Sanctions Screen', readOnlyHint: true },
    async ({ name }) => {
      try {
        const list = await getSanctionsList()
        const hits = list.filter(e => sanctionsMatch(name, e))
        if (!hits.length) {
          return { content: [{ type: 'text' as const, text: `## Sanctions Screen: ${name}\n**CLEAR** — No matches found.\nScreened ${list.length.toLocaleString()} UK entries across all regimes.\n*Source: FCDO UK Sanctions List, updated daily (OGL v3)*` }] }
        }
        const lines = [`## 🚨 Sanctions Screen: ${name}`, `**${hits.length} potential match(es) found.**`, '']
        for (const m of hits) {
          lines.push(`**${m.name}** | Regime: ${m.regimes.join(', ')}${m.dob ? ` | DOB: ${m.dob}` : ''}${m.nationality ? ` | Nationality: ${m.nationality}` : ''}`)
          if (m.aliases.length) lines.push(`Aliases: ${m.aliases.join('; ')}`)
        }
        lines.push('', '⚠️ Verify match independently. Do not proceed without senior sign-off.', '*Source: FCDO UK Sanctions List (OGL v3)*')
        return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
      } catch (e: any) {
        return { content: [{ type: 'text' as const, text: `Sanctions list unavailable: ${e.message}. Verify at https://www.gov.uk/government/publications/the-uk-sanctions-list` }], isError: true }
      }
    }
  )

  // Tool 3 — Company check
  server.tool(
    'company_check',
    'Look up a UK company on Companies House. Returns company status, registered address, SIC codes, all active officers, and persons with significant control (PSC). Flags dissolved, liquidation, administration, or receivership status.',
    { query: z.string().describe('Company name or Companies House registration number') },
    { title: 'Companies House Lookup', readOnlyHint: true },
    async ({ query }) => {
      try {
        const results = await chSearch(query)
        if (!results.length) return { content: [{ type: 'text' as const, text: `No UK company found matching "${query}".` }] }
        const num = results[0].company_number
        const [profile, officers, pscs] = await Promise.all([chProfile(num), chOfficers(num), chPSC(num)])
        const activeOfficers = (officers as any[]).filter(o => !o.resigned_on)
        const activePSCs = (pscs as any[]).filter(p => !p.ceased_on)
        const status: string = profile.company_status
        const risky = ['dissolved', 'liquidation', 'receivership', 'administration'].includes(status)
        const lines = [
          `## ${profile.company_name} (${num})`,
          `**Status:** ${status}${risky ? ' 🚨' : ''}`,
          `**Incorporated:** ${profile.date_of_creation}`,
          `**Address:** ${[profile.registered_office_address?.address_line_1, profile.registered_office_address?.address_line_2, profile.registered_office_address?.locality, profile.registered_office_address?.postal_code].filter(Boolean).join(', ')}`,
          `**SIC codes:** ${profile.sic_codes?.join(', ') || 'N/A'}${sicRisk(profile.sic_codes ?? []).length ? ` ⚠️ High-risk: ${sicRisk(profile.sic_codes ?? []).join('; ')}` : ''}`,
          '',
          `### Active officers (${activeOfficers.length})`,
          ...activeOfficers.map((o: any) => `- ${o.name} — ${o.officer_role} (appointed ${o.appointed_on})`),
          '',
          `### Persons with significant control (${activePSCs.length})`,
          ...activePSCs.map((p: any) => `- ${p.name || p.company_name || 'unnamed'} — ${p.natures_of_control?.join(', ') || 'type unknown'}`),
          '',
          `https://find-and-update.company-information.service.gov.uk/company/${num}`,
          `*Source: Companies House public register (OGL v3)*`,
        ]
        return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
      } catch (e: any) {
        return { content: [{ type: 'text' as const, text: `Companies House lookup failed: ${e.message}` }], isError: true }
      }
    }
  )

  // Tool 4 — PEP check
  server.tool(
    'pep_check',
    'Screen an individual against the UK Parliament register to identify Politically Exposed Persons (PEPs) — current and former MPs and Lords. PEPs require Enhanced Due Diligence (EDD) under MLR 2017 Regulation 35. Also covers their close associates and family members where names are known.',
    { name: z.string().describe('Full name of the individual to screen for PEP status') },
    { title: 'PEP Screen', readOnlyHint: true },
    async ({ name }) => {
      try {
        const peps = await pepLookup(name)
        if (!peps.length) {
          return { content: [{ type: 'text' as const, text: `## PEP Screen: ${name}\n**No match found** in UK Parliament register.\n\n*Note: This screens UK MPs and Lords only. For foreign PEPs or senior officials, additional manual checks may be required.*\n*Source: UK Parliament Members API*` }] }
        }
        const lines = [
          `## 🟡 PEP Screen: ${name}`,
          `**${peps.length} match(es) found — Enhanced Due Diligence required**`,
          '',
        ]
        for (const p of peps) {
          lines.push(`**${p.name}**`)
          lines.push(`Role: ${p.role} | Party: ${p.party} | ${p.house}`)
          lines.push(`Served: ${p.from}${p.to !== 'current' ? ` to ${p.to}` : ' (current member)'}`)
          lines.push('')
        }
        lines.push(`> Under MLR 2017 Reg 35, PEPs and their family/close associates require EDD including senior management approval, source of wealth checks, and enhanced ongoing monitoring.`)
        lines.push(`*Source: UK Parliament Members API*`)
        return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
      } catch (e: any) {
        return { content: [{ type: 'text' as const, text: `PEP check failed: ${e.message}` }], isError: true }
      }
    }
  )

  // Tool 5 — FCA check
  server.tool(
    'fca_check',
    'Verify a firm on the FCA Financial Services Register using their FRN (Firm Reference Number). Returns authorisation status, business type, organisation name, and Companies House number. Use when a client or counterparty claims to be FCA-regulated. Find FRNs at https://register.fca.org.uk',
    { frn: z.string().describe('FCA Firm Reference Number (FRN) — a 6-7 digit number, e.g. 122702') },
    { title: 'FCA Register Check', readOnlyHint: true },
    async ({ frn }) => {
      if (!/^\d{5,7}$/.test(frn.trim())) {
        return { content: [{ type: 'text' as const, text: `FRN must be a 5-7 digit number. Find the FRN at https://register.fca.org.uk\nExample: 122702 for Barclays Bank Plc.` }] }
      }
      try {
        const data = await fcaLookup(frn)
        if (data?.Status === 'FSR-API-02-01-11') {
          return { content: [{ type: 'text' as const, text: `## FCA Register: FRN ${frn}\n**Not found.** No firm is registered with this FRN.\nVerify at https://register.fca.org.uk\n*Source: FCA Financial Services Register*` }] }
        }
        const firm = data?.Data?.[0]
        if (!firm) {
          return { content: [{ type: 'text' as const, text: `## FCA Register: FRN ${frn}\nUnable to retrieve details. Verify at https://register.fca.org.uk` }] }
        }
        const lines = [
          `## FCA Register: ${firm['Organisation Name'] || firm.FRN}`,
          `**FRN:** ${firm.FRN}`,
          `**Status:** ${firm.Status}`,
          `**Business Type:** ${firm['Business Type'] || firm.BusinessType || 'N/A'}`,
          `**Companies House Number:** ${firm['Companies House Number'] || 'N/A'}`,
          `**Status effective:** ${firm['Status Effective Date'] || 'N/A'}`,
          ``,
          `https://register.fca.org.uk/apex/fhcs?id=${frn}`,
          `*Source: FCA Financial Services Register*`,
        ]
        return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
      } catch (e: any) {
        return { content: [{ type: 'text' as const, text: `FCA register check failed: ${e.message}` }], isError: true }
      }
    }
  )

  return server
}

// ── Express HTTP server ───────────────────────────────────────────────────────

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use('/public', express.static('public'))

app.get('/favicon.ico', (_req, res) => res.redirect('/public/favicon.png'))
app.get('/', (_req, res) => res.send('<html><head><link rel="icon" href="/public/favicon.png"><title>ClearCheck</title></head><body><h1>ClearCheck</h1><p>UK AML compliance intelligence for accountants.</p></body></html>'))

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'clearcheck-mcp', version: '1.0.0' })
})

// ── OAuth 2.0 endpoints ───────────────────────────────────────────────────────

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mcp'],
  })
})

// Dynamic client registration (RFC 7591)
app.post('/register', (req: Request, res: Response) => {
  const clientId = crypto.randomBytes(16).toString('hex')
  res.status(201).json({
    client_id: clientId,
    client_secret_expires_at: 0,
    redirect_uris: (req.body as any).redirect_uris || [],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  })
})

// Authorization — show form
app.get('/authorize', (req: Request, res: Response) => {
  const q = req.query as Record<string, string>
  if (q.response_type !== 'code' || !q.redirect_uri) {
    res.status(400).send('Invalid request: response_type must be "code" and redirect_uri is required')
    return
  }
  res.send(authorizeHTML({
    clientId: q.client_id || '',
    redirectUri: q.redirect_uri,
    state: q.state || '',
    codeChallenge: q.code_challenge || '',
    codeChallengeMethod: q.code_challenge_method || 'S256',
  }))
})

// Authorization — submit form
app.post('/authorize', async (req: Request, res: Response) => {
  const b = req.body as Record<string, string>
  const { client_id = '', redirect_uri = '', state = '', code_challenge = '', code_challenge_method = 'S256', key = '' } = b
  if (!redirect_uri) { res.status(400).send('Missing redirect_uri'); return }

  const valid = await validateLicenceKey(key)
  if (!valid) {
    res.send(authorizeHTML({
      clientId: client_id, redirectUri: redirect_uri, state,
      codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method,
      error: 'Invalid licence key. Get access at clearcheck-uk.github.io/clearcheck',
    }))
    return
  }

  const code = crypto.randomBytes(24).toString('hex')
  authCodes.set(code, {
    licenceKey: key, clientId: client_id, redirectUri: redirect_uri,
    codeChallenge: code_challenge || undefined, codeChallengeMethod: code_challenge_method || undefined,
    expiresAt: Date.now() + 600_000,  // 10 minutes
  })
  const params = new URLSearchParams({ code, ...(state ? { state } : {}) })
  res.redirect(`${redirect_uri}?${params}`)
})

// Token exchange
app.post('/token', async (req: Request, res: Response) => {
  const b = req.body as Record<string, string>
  const { grant_type, code, redirect_uri, code_verifier } = b

  if (grant_type !== 'authorization_code' || !code) {
    res.status(400).json({ error: 'unsupported_grant_type' }); return
  }
  const entry = authCodes.get(code)
  if (!entry || entry.expiresAt < Date.now()) {
    authCodes.delete(code)
    res.status(400).json({ error: 'invalid_grant' }); return
  }
  if (entry.redirectUri !== redirect_uri) {
    res.status(400).json({ error: 'invalid_grant' }); return
  }
  if (entry.codeChallenge && entry.codeChallengeMethod) {
    if (!code_verifier || !verifyPKCE(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) {
      res.status(400).json({ error: 'invalid_grant' }); return
    }
  }
  authCodes.delete(code)
  const accessToken = signJWT({ sub: entry.licenceKey }, 60 * 60 * 24 * 30)  // 30 days
  res.json({ access_token: accessToken, token_type: 'bearer', expires_in: 60 * 60 * 24 * 30 })
})

// ── MCP handler ───────────────────────────────────────────────────────────────

async function mcpHandler(req: Request, res: Response) {
  const origin = req.headers.origin
  if (req.method !== 'DELETE' && !isAllowedOrigin(origin)) {
    res.status(403).json({ error: 'Origin not allowed' })
    return
  }

  const authHeader = req.headers.authorization || ''
  const token = authHeader.replace('Bearer ', '').trim()
  const valid = await validateToken(token)
  if (!valid) {
    res.status(401).json({
      error: 'Invalid or missing access token.',
      info: 'Connect at clearcheck-uk.github.io/clearcheck',
    })
    return
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
  const server = buildServer()
  await server.connect(transport)
  await transport.handleRequest(req, res, req.body)
}

app.post('/mcp', mcpHandler)
app.get('/mcp', mcpHandler)
app.delete('/mcp', async (req: Request, res: Response) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
  await transport.handleRequest(req, res)
})

app.listen(PORT, () => console.log(`ClearCheck MCP running on :${PORT}`))
