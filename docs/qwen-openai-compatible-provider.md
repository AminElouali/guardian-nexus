# External Qwen proposal demo

Guardian Nexus can request one fixed synthetic refund proposal from an
administrator-configured OpenAI-compatible inference endpoint. The API server
reads `QWEN_PROVIDER_BASE_URL`, `QWEN_PROVIDER_MODEL`, and the secret
`QWEN_PROVIDER_API_KEY` from its runtime environment. Add the key through
Replit Secrets; never place it in source, browser code, request bodies, logs,
or an exported approval bundle.

The server accepts only an HTTPS endpoint without embedded credentials,
query parameters, fragments, local hostnames, or IP-literal hosts. It sends a
fixed synthetic task and offers exactly one proposal tool. The response must
contain exactly one call to that tool, with only the expected synthetic ticket
and amount fields. Guardian then independently checks the proposal against
the existing allowlisted action and policy preview. The model cannot select a
policy decision, approve an action, invoke a protected tool, or run the
simulator.

An accepted proposal creates the same pending human-approval request used by
the fixture path. Approval still requires a different eligible workspace
owner/admin and produces the existing signed receipt. The simulator remains
in-memory and can run only through the existing receipt-consumption path.
Provider evidence records fixed metadata and hashes, not the prompt,
response, raw arguments, API key, or endpoint URL.

The `/ai-evaluations` page labels this as external inference and separately
labels deterministic fixtures. The provider status endpoint reports only
whether the configuration is absent, syntactically invalid, or configured
but not connectivity-tested. A configured status does not prove that the
provider is reachable or that credentials work.

Local automated tests mock the provider response and must not be described as
real inference. No provider request should be run until the workspace owner
has configured the endpoint, model, and Replit secret. Even with HTTPS and
host syntax checks, DNS resolution and provider-side processing are outside
the application's trust boundary; configure only a provider endpoint approved
for synthetic test prompts.

An optional one-request provider check is available as
`QWEN_PROVIDER_INTEGRATION=1 pnpm --filter @workspace/api-server exec tsx --test src/lib/qwen-openai-provider.integration.test.ts`.
It reads the same three runtime settings and makes one real provider request.
It is intentionally not part of the default test suite and has not been run
as part of this implementation.
