# STIG Condenser — React SPA (GovCloud)

The frontend for the GovCloud deployment. The Flask UI in `../app/` is **not**
replaced by this — it remains the zero-infrastructure way to run the tool
locally or air-gapped. This SPA exists because the GovCloud runtime is
serverless and async, and that API needs a client.

**Design:** `../docs/superpowers/specs/2026-07-14-react-frontend-design.md`

## Develop

```sh
npm install
VITE_API_BASE=https://<private-api>/v1 npm run dev
```

`VITE_API_BASE` is the only environment-specific value in the bundle. It is a
VPC-internal URL — not a secret, but it is injected at build time and never
committed.

## Test

```sh
npm test          # Vitest + React Testing Library + axe
npm run e2e       # Playwright against a mocked API
npx tsc --noEmit  # types
```

There are no tests against a live API: that would need GovCloud credentials, and
public CI does not have them (and must not).

## Build & deploy

```sh
VITE_API_BASE=https://<private-api>/v1 npm run build   # -> dist/
aws s3 sync dist/ s3://<spa_bucket>/ --delete          # operator/CD step
```

The bucket is `spa_bucket` from the Terraform `api` module, served through the
Private API Gateway S3 proxy (D6). Like `terraform apply`, the sync is an
operator action — public CI builds and tests the bundle but never holds
credentials.

## Notes

- **Uploads bypass the API.** Files are PUT straight to S3 with presigned urls,
  which is what keeps a 200 MB scan clear of API Gateway's 29-second ceiling.
  Presigned urls live 15 minutes; a slow upload can outlive one, and the UI
  reports that rather than pretending the job started.
- **The AI toggle is disabled with a stated reason** when no Bedrock model is
  approved. Off is never silent.
- **The stylesheet is ported from the Flask app** and keeps its class names, so
  the audited WCAG AA contrast pairs and focus rings carry over unchanged. Do
  not restyle it casually.
