# Offline email/database adapted-marker injection matrix

Date: 2026-11-10

## Scope

Starting HEAD: `29aaed43502fc3db59d04ef0e4a38b9387270c9d` (`main`).
The only code change is a parameterized test in
`tests/test_policy_lab.py`. It feeds fixed synthetic `<tool_call>` marker
responses through the existing adapter, argument validation, and independent
Policy Engine for every currently defined adversarial email and database case.
Two benign read controls verify that an allowed Policy ON decision occurs
before synthetic dispatch.

The response provider is a fixed test double. This is not Qwen inference and is
not counted as native runtime `message.tool_calls` or as a baseline fixture.
No production code or fixture files were changed.

## Results

Command, run from `workers/guardian-ai-assessment`:

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest tests.test_policy_lab.GuardianAgentPolicyLabTests.test_all_email_database_adversarial_adapted_markers_are_policy_gated -v`

- Final result: **1 test passed; 10 parameterized cases passed** (four email
  adversarial cases, four database adversarial cases, and two benign read
  controls).
- The eight adversarial proposals were denied and never reached the simulator;
  no execution events were recorded.
- For both benign controls, Policy ON was observed before the single synthetic
  dispatch.
- Every response was labeled
  `guardian_qwen_native_markup_adapter`, not runtime-native and not fixture
  provenance. Policy OFF was asserted to be `counterfactual_clone_only` with
  `executed=false`; its path did not invoke the simulator.
- `git diff --check` passed.

The first targeted run failed eight adversarial subcases because the new test
expected generic reason codes. The actual existing Policy Engine returned the
more specific denials `external_email_tool_never_executable` and
`database_mutation_proposal_not_executable`. Only test expectations were
corrected; no product-code defect was found. The final targeted run passed.

## Safety and limits

Only this offline unit test was run. No Qwen/model, worker, broker, Docker,
PostgreSQL, API, E2E, external service, or real data was used. The test
demonstrates deterministic contract behavior with fixed responses, not model
behavior or live integration.

## SHA-256

- `tests/test_policy_lab.py`:
  `a32c28afd678b0892e28f24d6eeb0e992b5578e679dd0f162f52ff7a136e5b5d`
