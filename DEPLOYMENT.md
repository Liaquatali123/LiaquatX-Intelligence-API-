# Deployment guide

## GitHub Actions secrets

Add these under Settings → Secrets and variables → Actions:

1. CLOUDFLARE_ACCOUNT_ID
2. CLOUDFLARE_API_TOKEN (Cloudflare account-scoped token with Workers Scripts: Edit and D1: Edit)
3. ADMIN_SECRET (a random secret with at least 32 bytes)

Never commit these values.

## First deployment

After adding the secrets, open Actions → Deploy LiaquatX Intelligence API → Run workflow. The workflow creates or reuses the D1 database, applies db/schema.sql, runs TypeScript type-checking, sets ADMIN_SECRET, and deploys the Worker and public assets.

Subsequent pushes to main trigger deployments automatically.

## Provision an API key

After deployment, send a POST request to /v1/admin/keys with JSON { "email": "customer@example.com", "plan": "free", "label": "Customer" } and the x-admin-secret header. The response contains the API key once; store it securely.

## Current MVP scope

Implemented: health, website status, SEO metadata, security-header inspection, technology hints, API key provisioning, and daily quota accounting.

Not yet implemented: customer self-service registration/login, DNS/WHOIS/SSL/redirect endpoints, screenshot capture, subscription checkout, Binance Pay reconciliation, email verification, password reset, and a complete admin web console.

Security warning: current hostname checks do not fully prevent DNS rebinding. Do not expose arbitrary URL scanning to untrusted public traffic until DNS resolution/IP pinning or a dedicated outbound proxy is implemented and independently tested.
