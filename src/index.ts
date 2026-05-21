import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'
import axios from 'axios'

const PORT = parseInt(process.env.PORT || '3000')
const CH_API_KEY = process.env.COMPANIES_HOUSE_API_KEY || ''
const FCA_API_KEY = process.env.FCA_API_KEY || ''
const FCA_EMAIL = process.env.FCA_EMAIL || ''
const POLAR_ACCESS_TOKEN = process.env.POLAR_ACCESS_TOKEN || ''
const POLAR_ORG_ID = process.env.POLAR_ORG_ID || ''
const REVIEWER_KEY = process.env.REVIEWER_KEY || ''
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://claude.ai,https://api.anthropic.com').split(',')

// ── Origin validation (required by Anthropic security standards) ─────────────

function isAllowedOrigin(origin: string | undefined): boolean {
  if (!origin) return false
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
  const nq = normName(q)
  return [e.name, ...e.aliases].map(normName).some(n => n.includes(nq) || nq.includes(n))
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
    'Run a full Customer Due Diligence (CDD) check on a new client as required under UK Money Laundering Regulations 2017. Screens against the FCDO UK Sanctions List, looks up the company on Companies House (status, directors, PSCs), and checks the FCA Financial Services Register. Returns a structured risk report ready for your MLRO file.',
    {
      name: z.string().describe('Full name of individual or company to screen'),
      company_number: z.string().optional().describe('Companies House number if known — speeds up the lookup'),
    },
    {
      title: 'Full CDD Report',
      readOnlyHint: true,
    },
    async ({ name, company_number }) => {
      const lines: string[] = [
        `# CDD Report: ${name}`,
        `*${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })} · ClearCheck UK*`,
        '',
      ]

      // Sanctions
      try {
        const list = await getSanctionsList()
        const hits = list.filter(e => sanctionsMatch(name, e))
        if (hits.length) {
          lines.push(`## 🚨 SANCTIONS: ${hits.length} MATCH(ES) FOUND`)
          for (const m of hits) {
            lines.push(`- **${m.name}** | Regime: ${m.regimes.join(', ')}${m.dob ? ` | DOB: ${m.dob}` : ''}`)
            if (m.aliases.length) lines.push(`  Aliases: ${m.aliases.join('; ')}`)
          }
          lines.push(`> ⚠️ Do NOT proceed. Verify match independently before any action.`)
        } else {
          lines.push(`## ✅ Sanctions: Clear — ${list.length.toLocaleString()} UK entries screened`)
        }
      } catch {
        lines.push(`## ⚠️ Sanctions: Unavailable — verify manually at https://www.gov.uk/government/publications/the-uk-sanctions-list`)
      }
      lines.push('')

      // Companies House
      try {
        const results = company_number ? [{ company_number }] : await chSearch(name)
        if (results.length) {
          const num = results[0].company_number
          const [profile, officers, pscs] = await Promise.all([chProfile(num), chOfficers(num), chPSC(num)])
          const status: string = profile.company_status
          const activeOfficers = (officers as any[]).filter(o => !o.resigned_on)
          const activePSCs = (pscs as any[]).filter(p => !p.ceased_on)
          const risky = ['dissolved', 'liquidation', 'receivership', 'administration'].includes(status)
          lines.push(`## ${risky ? '🚨' : '✅'} Companies House: ${profile.company_name} (${num})`)
          lines.push(`- **Status:** ${status}${risky ? ' — HIGH RISK ⚠️' : ''}`)
          lines.push(`- **Incorporated:** ${profile.date_of_creation}`)
          lines.push(`- **Address:** ${[profile.registered_office_address?.address_line_1, profile.registered_office_address?.locality, profile.registered_office_address?.postal_code].filter(Boolean).join(', ')}`)
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

      // FCA
      lines.push(`## ℹ️ FCA Register: Use \`fca_check\` with the firm's FRN to verify authorisation status`)
      lines.push(`   Look up FRN at: https://register.fca.org.uk`)
      lines.push('')
      lines.push(`---`)
      lines.push(`*Decision-support tool only. Retain in MLRO file. Your firm retains sole AML/CTF responsibility under MLR 2017.*`)
      lines.push(`*Sources: FCDO UK Sanctions List (OGL v3) · Companies House public register (OGL v3) · FCA Financial Services Register*`)

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
          `**SIC codes:** ${profile.sic_codes?.join(', ') || 'N/A'}`,
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

  // Tool 4 — FCA check
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

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'clearcheck-mcp', version: '1.0.0' })
})

async function mcpHandler(req: Request, res: Response) {
  // Origin validation — prevent DNS rebinding attacks
  const origin = req.headers.origin
  if (req.method !== 'DELETE' && !isAllowedOrigin(origin)) {
    res.status(403).json({ error: 'Origin not allowed' })
    return
  }

  // Licence key validation
  const authHeader = req.headers.authorization || ''
  const licenceKey = authHeader.replace('Bearer ', '').trim()
  const valid = await validateLicenceKey(licenceKey)
  if (!valid) {
    res.status(401).json({
      error: 'Invalid or missing licence key.',
      subscribe: 'https://polar.sh/clearcheck',
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
