# Design decisions

| Decision | Why | Trade-off |
|---|---|---|
| Serverless only (no VPC, NAT, RDS, EKS) | Near-zero cost, nothing to patch, fits free tier | No long-running scans (Lambda max 15 min) |
| API Gateway **HTTP API** for REST | Cheaper, built-in JWT check; it is REST-style routing | Fewer features than REST API (no usage plans) |
| SQS between API and worker | API answers instantly (202); retries; DLQ for poison messages | Result arrives asynchronously, hence the WebSocket |
| WebSocket for live updates | Dashboard updates without polling | Needs connection table + cleanup (TTL + 410 handling) |
| Single DynamoDB table | One table, pay per request, TTL for connections | All findings share one partition key (fine at this size) |
| Stable finding id (hash) | Idempotent re-scans, easy "fixed" detection | A renamed resource looks like new + fixed |
| "Fixed" only for trusted rules/regions | A permission error must not hide a real problem | Slightly more bookkeeping |
| One IAM role per Lambda | Blast radius stays small | More Terraform |
| OIDC for GitHub Actions | No long-lived keys in GitHub | One-time bootstrap |
| Dashboard files uploaded by Terraform | One `apply` deploys everything | Not a separate frontend pipeline |
| Cognito `USER_PASSWORD_AUTH` | Simple custom login page | Production would use hosted UI + PKCE |

## Known gaps / next steps
- Use Cognito hosted UI with PKCE instead of password flow.
- Tighten the CI deploy role (currently PowerUser + IAM limited to `cloudguard-*`).
- Add AWS WAF in front of CloudFront (paid, so left out).
- Add more rules (KMS rotation, RDS public access, EBS encryption).
- Separate `prod` state key / account.
