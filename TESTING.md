# Release validation

- [ ] npm ci
- [ ] npm run typecheck
- [ ] npm run db:local
- [ ] npm run dev and verify /health
- [ ] Verify invalid API keys return 401.
- [ ] Verify quota enforcement returns 429.
- [ ] Verify private/local targets are rejected.
- [ ] Verify redirects to private/local targets are rejected.
- [ ] Verify oversized responses and slow targets fail safely.
- [ ] Configure ADMIN_SECRET before creating production API keys.

Security note: hostname string checks alone do not fully prevent DNS rebinding. Before exposing arbitrary URL analysis publicly, add DNS resolution/IP pinning or a dedicated outbound fetch proxy and conduct an independent security review.
