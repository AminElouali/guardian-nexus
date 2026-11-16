import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  parseQwenProviderConfig,
  providerProposalMatchesAllowlistedAction,
  requestQwenRefundProposal,
} from "./qwen-openai-provider";

const integrationEnabled = process.env.QWEN_PROVIDER_INTEGRATION === "1";

test(
  "optional external Qwen inference returns only the exact synthetic allowlisted proposal",
  { skip: !integrationEnabled, timeout: 30_000 },
  async () => {
    const config = parseQwenProviderConfig(process.env);
    const proposal = await requestQwenRefundProposal(config);
    const expectedArgumentsSha256 = createHash("sha256")
      .update(
        '{"amount_cents":500,"ticket_id":"TICKET-SYNTH-001"}',
        "utf8",
      )
      .digest("hex");

    assert.equal(
      providerProposalMatchesAllowlistedAction(
        proposal,
        expectedArgumentsSha256,
      ),
      true,
    );
    assert.equal(proposal.arguments.ticket_id, "TICKET-SYNTH-001");
    assert.equal(proposal.arguments.amount_cents, 500);
    assert.equal(proposal.toolName, "propose_synthetic_refund");
    assert.equal("execute" in proposal, false);
  },
);
