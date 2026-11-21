# Deployment guide

## GitHub Actions secrets

Add these under Settings → Secrets and variables → Actions:

1. `CLOUDFLARE_ACCOUNT_ID`
2. `CLOUDFLARE_API_TOKEN` (Cloudflare account-scoped token with Workers Scripts: Edit and D1: Edit)
3. `ADMIN_SECRET` (a random secret with at least 32 bytes)

Optional Worker secret:
4. `OPENPAGERANK_API_KEY` — required only for the backlink endpoint. Register with Open PageRank, then add this as a Worker secret using Wrangler or Cloudflare Dashboard → Workers & Pages → Settings → Variables and Secrets.

Never commit secret values.

## First deployment

Open Actions → Deploy LiaquatX Intelligence API → Run workflow. The workflow creates or reuses the D1 database, applies `db/schema.sql`, runs TypeScript type-checking, configures `ADMIN_SECRET`, and deploys the Worker and public assets. Subsequent pushes to main trigger deployments automatically.

## Admin and API keys

Admin dashboard: `https://liaquatx-intelligence-api.rdxkinglucky.workers.dev`

The dashboard requires `ADMIN_SECRET`. Generate keys from its Generate key tab. The full API key is displayed only once.

## Available non-AI endpoints

All endpoints below require `x-api-key`, except `/health` and admin endpoints.

| Endpoint | Query | Function |
|---|---|---|
| `GET /health` | — | Worker health |
| `GET /v1/website/check` | `url` | Website status |
| `GET /v1/website/seo` | `url` | Title, description and basic SEO tags |
| `GET /v1/website/headers` | `url` | Security header checks |
| `GET /v1/website/technologies` | `url` | Technology hints |
| `GET /v1/website/dns` | `domain` | A, AAAA, MX, NS, TXT, CNAME and SOA records |
| `GET /v1/domain/whois` | `domain` | RDAP registration data |
| `GET /v1/website/ssl` | `domain` | SSL Labs status and grade |
| `GET /v1/website/redirects` | `url` | Redirect chain |
| `GET /v1/website/screenshot` | `url` | External screenshot URL |
| `GET /v1/website/pagespeed` | `url`, optional `strategy=mobile|desktop` | Google PageSpeed/Lighthouse scores |
| `GET /v1/website/broken-links` | `url` | Checks up to 30 page links |
| `GET /v1/domain/availability` | `domain` | RDAP registration status |
| `GET /v1/domain/backlinks` | `domain` | Open PageRank data; requires `OPENPAGERANK_API_KEY` |
| `GET /v1/account/usage` | — | Daily usage and plan quota |

## Provider notes and limits

- DNS uses Cloudflare DNS-over-HTTPS.
- WHOIS-style registration data and availability use RDAP. A registry may return limited fields; a negative RDAP response is not a guarantee that a domain can be purchased immediately.
- SSL grade data comes from SSL Labs. First-time scans may be pending or require a later retry; cached results are preferred.
- Screenshot capture returns a URL from thum.io; it is an external provider, not a screenshot stored by this Worker.
- PageSpeed uses Google's PageSpeed Insights API. Provider quotas and scan duration apply.
- Broken-link scan checks at most 30 unique HTTP/HTTPS links to keep execution bounded. Some sites block automated HEAD requests.
- Backlink data is provided by Open PageRank and is not a full commercial backlink index. Configure the optional API key.
- All these features are rule-based/provider-backed. No AI model, AI chatbot, or AI-generated SEO report is included.

## Security note

The current hostname validation blocks common private/local address patterns, but it does not fully prevent DNS rebinding. Before exposing arbitrary URL scanning to untrusted public traffic, add DNS resolution/IP pinning or a dedicated outbound proxy and independently test it. External provider availability and rate limits can affect results.
