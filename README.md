# LiaquatX Intelligence API

Cloudflare Workers + D1 website-intelligence API with a premium dark-glass dashboard.

## Automatic deployment

Every push to `main` runs GitHub Actions. It installs dependencies, creates or reuses the Cloudflare D1 database `liaquatx-db`, writes its UUID into `wrangler.toml`, applies the idempotent SQL schema, type-checks the project, configures Worker secrets, and deploys the Worker and static dashboard.

### One-time GitHub Actions secrets

In **Settings → Secrets and variables → Actions**, add:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN` — create a scoped token with Workers Scripts: Edit, D1: Edit, and account access for this Cloudflare account
- `ADMIN_SECRET` — generate a long random secret (at least 32 random bytes)
- `BINANCE_PAY_ID` — your Binance Pay recipient ID (never commit this value)

After these are saved, push to `main` or select **Actions → Deploy LiaquatX Intelligence API → Run workflow**.

The first successful deployment provisions the D1 database automatically. The public URL will be printed in the GitHub Actions deployment log and will use your Cloudflare `workers.dev` subdomain.

## Important

- Never put Cloudflare tokens, admin secrets, or payment credentials in source code.
- Binance payments are manually reconciled by the admin; a submitted transaction reference is not proof of payment.
- Review the security limitations in the project documentation before offering public URL-scanning access.
