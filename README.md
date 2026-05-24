# ClearCheck — UK Compliance Intelligence for Claude

Run AML and due diligence checks on UK companies and individuals directly inside Claude.

Designed for UK accountants, bookkeepers, and compliance professionals required to perform Customer Due Diligence (CDD) under the Money Laundering Regulations 2017.

## What it does

Ask Claude to check any UK company or individual and ClearCheck instantly screens against:

- **Companies House** — company status, directors, persons with significant control
- **FCDO UK Sanctions List** — all UK sanctions regimes, updated daily
- **FCA Financial Services Register** — authorisation status
- **Red flag detection** — dissolved, liquidation, administration, receivership flags

## Example usage

```
Run a full CDD check on John Davies, director of Meridian Consulting Ltd
```

```
Screen ABC Holdings Ltd before we onboard them as a new audit client
```

```
Quick sanctions check on Vladimir Petrov
```

## Tools

| Tool | Description |
|---|---|
| `client_cdd` | Full CDD report — sanctions + PEP + Companies House + risk rating |
| `sanctions_screen` | UK sanctions list check (FCDO, all regimes) |
| `pep_check` | Politically Exposed Person screen via UK Parliament register |
| `company_check` | Companies House profile, officers, PSCs |
| `fca_check` | FCA Financial Services Register lookup by FRN |

## Setup

1. Get a licence key at [clearcheck-uk.github.io/clearcheck](https://clearcheck-uk.github.io/clearcheck)
2. Add to Claude Desktop config:

```json
{
  "mcpServers": {
    "clearcheck": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://clearcheck.onrender.com/mcp", "--header", "Authorization:Bearer YOUR_LICENCE_KEY"]
    }
  }
}
```

3. Restart Claude Desktop — ClearCheck tools are ready

## Pricing

£99/month — unlimited checks, all tools included

## Terms of Service

By using ClearCheck you agree to: (1) use the service only for lawful compliance purposes; (2) not attempt to reverse-engineer or abuse the API; (3) accept that results are provided for decision-support only and carry no legal warranty; (4) maintain your own AML/CTF compliance obligations under applicable law. Subscriptions are billed monthly and may be cancelled at any time. ClearCheck reserves the right to suspend access for misuse. Governed by the laws of England and Wales.

## Legal

ClearCheck is a decision-support tool. It is not legal or compliance advice. Your firm retains sole responsibility for AML/CTF compliance obligations under the Money Laundering Regulations 2017. Always apply professional judgment to results.

Data sources:
- UK Sanctions List © Crown Copyright, published under Open Government Licence v3.0
- Companies House data, published under Open Government Licence v3.0
- FCA Financial Services Register

## Privacy Policy

See [PRIVACY.md](./PRIVACY.md)

## Support

traveltaxdesk@gmail.com
