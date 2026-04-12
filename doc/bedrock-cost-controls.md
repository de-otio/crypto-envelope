# CI — Bedrock migration and cost controls

## Bedrock support

All three AI workflows support AWS Bedrock as a drop-in replacement for the
direct Anthropic API. Required changes per workflow:

All workflows authenticate to AWS via GitHub's OIDC provider — no
long-lived access keys are stored as secrets. Each job that calls Bedrock
must declare `permissions: id-token: write` and assume the
`github-ci-bedrock` role before invoking the model.

### `security-review.yml` and `claude-agent.yml`

Both use `anthropics/claude-code-security-review` /
`anthropics/claude-code-action`. Assume the role first, then set
`use_bedrock: true`:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@<sha>
    with:
      role-to-assume: arn:aws:iam::284064533851:role/github-ci-bedrock
      aws-region: eu-central-1

  - name: Run Claude Security Review
    uses: anthropics/claude-code-security-review@<sha>
    with:
      use_bedrock: true
      aws_region: eu-central-1
```

### `weekly-security-audit.yml`

Same OIDC role assumption, then the `claude` CLI picks up the ambient AWS
credentials from the environment:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@<sha>
    with:
      role-to-assume: arn:aws:iam::284064533851:role/github-ci-bedrock
      aws-region: eu-central-1

  - name: Run deep security audit
    env:
      CLAUDE_CODE_USE_BEDROCK: "1"
      AWS_REGION: eu-central-1
    run: |
      claude --model eu.anthropic.claude-opus-4-6-20251101-v1:0 \
             --max-turns 15 --print <<'PROMPT' > audit-report.md
      ...
```

### Model ID mapping

| Anthropic API | Bedrock model ID |
|---|---|
| `claude-opus-4-6` | `eu.anthropic.claude-opus-4-6-20251101-v1:0` |
| `claude-sonnet-4-6` | `eu.anthropic.claude-sonnet-4-6-20251101-v1:0` |

---

## Cost controls

### Layer 1 — per-run hard limits (in-repo)

These limit the maximum cost of a single workflow run.

| Workflow | `timeout-minutes` | `--max-turns` | Status |
|---|---|---|---|
| `security-review.yml` | 10 | handled by action | OK |
| `weekly-security-audit.yml` | 30 | 15 | OK |
| `claude-agent.yml` | 10 | 10 | OK |

### Layer 2 — AWS Budget circuit breaker (outside this repo)

This is the only mechanism that actually stops spend mid-month rather
than alerting after the fact.

**IAM role** (`github-ci-bedrock`): restrict to `bedrock:InvokeModel` on the
specific model ARNs in use. No other Bedrock or AWS permissions.

```json
{
  "Effect": "Allow",
  "Action": "bedrock:InvokeModel",
  "Resource": [
    "arn:aws:bedrock:eu-central-1::foundation-model/eu.anthropic.claude-opus-4-6-20251101-v1:0",
    "arn:aws:bedrock:eu-central-1::foundation-model/eu.anthropic.claude-sonnet-4-6-20251101-v1:0"
  ]
}
```

**AWS Budget**: create a monthly budget scoped to this IAM role with two
thresholds:

| Threshold | Action |
|---|---|
| 80% of limit | SNS alert to on-call |
| 100% of limit | SNS → Lambda that attaches a Deny policy to the role |

**Circuit-breaker Lambda** (Node.js, ~20 lines):

```javascript
import { IAMClient, PutRolePolicyCommand } from "@aws-sdk/client-iam";

export const handler = async () => {
  const iam = new IAMClient({});
  await iam.send(new PutRolePolicyCommand({
    RoleName: "github-ci-bedrock",
    PolicyName: "budget-circuit-breaker",
    PolicyDocument: JSON.stringify({
      Version: "2012-10-17",
      Statement: [{
        Effect: "Deny",
        Action: "bedrock:*",
        Resource: "*",
      }],
    }),
  }));
  console.log("Circuit breaker engaged: Bedrock access denied on github-ci-bedrock");
};
```

To reset: delete the `budget-circuit-breaker` inline policy from the role in
the AWS console (or via CLI: `aws iam delete-role-policy --role-name
github-ci-bedrock --policy-name budget-circuit-breaker`).

### Layer 3 — structural limits (already in place)

- Concurrency groups prevent parallel runs on the same PR.
- Security review skips draft PRs.
- Weekly audit runs on schedule, not on every push.
- Agent only fires on explicit `@claude` mentions.

---

## Biggest cost risk

`claude-agent.yml` has no `timeout-minutes` and anyone with comment access
can trigger it repeatedly. Back-to-back triggers are serialised by the
concurrency group (cancel-in-progress) but sequential triggers are not
rate-limited. Mitigations:

1. Add `timeout-minutes: 10`.
2. Set `allowed_non_write_users: ""` in the action inputs to restrict
   triggering to repo collaborators with write access.
3. The AWS Budget circuit breaker (Layer 2) is the backstop for any
   scenario that gets past the above.
