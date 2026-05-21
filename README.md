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
| `client_cdd` | Full CDD report — sanctions + Companies House + FCA + risk summary |
| `sanctions_screen` | UK sanctions list check (FCDO, all regimes) |
| `company_check` | Companies House profile, officers, PSCs |
| `fca_check` | FCA Financial Services Register lookup |

## Setup

1. Subscribe at [polar.sh/clearcheck](https://polar.sh/clearcheck) to get your licence key
2. Add to Claude Desktop config:

```json
{
  "mcpServers": {
    "clearcheck": {
      "url": "https://clearcheck-mcp.railway.app/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_LICENCE_KEY"
      }
    }
  }
}
```

3. Restart Claude Desktop — ClearCheck tools are ready

## Pricing

£99/month — unlimited checks, all tools included

## Legal

ClearCheck is a decision-support tool. It is not legal or compliance advice. Your firm retains sole responsibility for AML/CTF compliance obligations under the Money Laundering Regulations 2017. Always apply professional judgment to results.

Data sources:
- UK Sanctions List © Crown Copyright, published under Open Government Licence v3.0
- Companies House data, published under Open Government Licence v3.0
- FCA Financial Services Register

## Privacy Policy

See [PRIVACY.md](./PRIVACY.md)

## Support

mcp-review@clearcheck.co.uk
