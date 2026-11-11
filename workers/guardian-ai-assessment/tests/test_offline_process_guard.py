import json
import inspect
import socket
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import patch

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment import offline_process_guard, offline_qwen_runner
from guardian_ai_assessment import llm_lab
from guardian_ai_assessment import qwen_policy_lab


class OfflineProcessGuardTests(unittest.TestCase):
    def test_invalid_guard_proof_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "offline_guard_proof_invalid"):
            offline_process_guard.offline_network_evidence(object())
        with self.assertRaisesRegex(RuntimeError, "offline_guard_proof_invalid"):
            offline_process_guard.offline_limit_evidence(object())

    def test_unsupported_architecture_fails_closed_before_installation(self):
        with patch.object(offline_process_guard.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(
                RuntimeError, "offline_seccomp_architecture_unsupported"
            ):
                offline_process_guard.install_offline_process_guard()

    def test_seccomp_guard_persists_limits_and_denies_sockets_and_exec(self):
        child = textwrap.dedent(
            """
            import errno
            import json
            import os
            import socket
            import sys
            import threading
            from pathlib import Path
            import ctypes

            sys.path.insert(0, str(Path(sys.argv[1])))
            from guardian_ai_assessment.offline_process_guard import (
                install_offline_process_guard,
                offline_limit_evidence,
                offline_network_evidence,
            )

            proof = install_offline_process_guard()
            network = offline_network_evidence(proof)
            limits = offline_limit_evidence(proof)
            socket_denials = []
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    socket.socket(family, socket.SOCK_STREAM)
                except OSError as exc:
                    socket_denials.append(exc.errno == errno.EPERM)
                else:
                    socket_denials.append(False)
            try:
                os.execve("/bin/true", ["true"], {})
            except OSError as exc:
                exec_denied = exc.errno == errno.EPERM
            else:
                exec_denied = False

            thread_result = []
            thread = threading.Thread(target=lambda: thread_result.append("thread-ok"))
            thread.start()
            thread.join(timeout=2)
            thread_created = not thread.is_alive() and thread_result == ["thread-ok"]

            try:
                os.fork()
            except OSError as exc:
                fork_denied = exc.errno == errno.EPERM
            else:
                fork_denied = False
                os.wait()

            libc = ctypes.CDLL(None, use_errno=True)
            syscall = libc.syscall
            syscall.restype = ctypes.c_long
            syscall.argtypes = [
                ctypes.c_long, ctypes.c_ulong, ctypes.c_ulong,
                ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
            ]
            clone3_result = syscall(435, 0, 0, 0, 0, 0)
            clone3_errno = ctypes.get_errno()
            # Missing CLONE_THREAD and a namespace/process flag are denied
            # before the kernel can create a process.
            clone_missing_thread = syscall(56, 0, 0, 0, 0, 0)
            clone_missing_thread_errno = ctypes.get_errno()
            clone_namespace = syscall(56, 0x00010100 | 0x02000000, 0, 0, 0, 0)
            clone_namespace_errno = ctypes.get_errno()
            # If vfork were unexpectedly allowed, its child exits immediately
            # inside this disposable test subprocess; the expected path is
            # EPERM before a child is created.
            ctypes.set_errno(0)
            vfork_result = syscall(58, 0, 0, 0, 0, 0)
            if vfork_result == 0:
                libc._exit(99)
            vfork_errno = ctypes.get_errno()
            if vfork_result > 0:
                os.waitpid(vfork_result, 0)
            execveat_path = ctypes.create_string_buffer(b"/bin/true")
            ctypes.set_errno(0)
            execveat_result = syscall(
                322, 0xFFFFFFFF, ctypes.addressof(execveat_path), 0, 0, 0
            )
            execveat_errno = ctypes.get_errno()
            print(json.dumps({
                "network": network,
                "limits": limits,
                "socketDenials": socket_denials,
                "execDenied": exec_denied,
                "threadCreated": thread_created,
                "forkDenied": fork_denied,
                "clone3Errno": clone3_errno,
                "clone3Result": clone3_result,
                "cloneMissingThreadErrno": clone_missing_thread_errno,
                "cloneMissingThreadResult": clone_missing_thread,
                "cloneNamespaceErrno": clone_namespace_errno,
                "cloneNamespaceResult": clone_namespace,
                "vforkErrno": vfork_errno,
                "vforkResult": vfork_result,
                "execveatErrno": execveat_errno,
                "execveatResult": execveat_result,
            }, sort_keys=True))
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", child, str(WORKER_ROOT)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        evidence = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(evidence["network"]["seccompMode"], 2)
        self.assertTrue(evidence["network"]["noNewPrivileges"])
        self.assertEqual(evidence["network"]["externalCalls"], 0)
        self.assertEqual(evidence["network"]["ipv6Capability"], "not_verified")
        self.assertEqual(evidence["network"]["destinationReachabilityProbes"], "not_performed")
        self.assertEqual(evidence["socketDenials"], [True, True])
        self.assertTrue(evidence["execDenied"])
        self.assertTrue(evidence["threadCreated"])
        self.assertTrue(evidence["forkDenied"])
        self.assertEqual(evidence["clone3Result"], -1)
        self.assertEqual(evidence["clone3Errno"], 38)  # ENOSYS
        self.assertEqual(evidence["cloneMissingThreadResult"], -1)
        self.assertEqual(evidence["cloneMissingThreadErrno"], 1)  # EPERM
        self.assertEqual(evidence["cloneNamespaceResult"], -1)
        self.assertEqual(evidence["cloneNamespaceErrno"], 1)  # EPERM
        self.assertEqual(evidence["vforkResult"], -1)
        self.assertEqual(evidence["vforkErrno"], 1)  # EPERM
        self.assertEqual(evidence["execveatResult"], -1)
        self.assertEqual(evidence["execveatErrno"], 1)  # EPERM
        self.assertEqual(evidence["limits"]["cpuAffinityCount"], 1)
        self.assertEqual(evidence["limits"]["concurrency"], 1)
        self.assertTrue(evidence["limits"]["limitsVerified"])


class OfflineRunnerDockerPrivilegeTests(unittest.TestCase):
    def test_per_case_timeout_is_bounded_by_profile_and_overall_limits(self):
        self.assertEqual(
            offline_qwen_runner._bounded_case_timeout_seconds(
                wall_deadline=500,
                per_case_seconds=180,
                now=100,
            ),
            180,
        )
        self.assertEqual(
            offline_qwen_runner._bounded_case_timeout_seconds(
                wall_deadline=250,
                per_case_seconds=180,
                now=100,
            ),
            150,
        )
        with self.assertRaisesRegex(TimeoutError, "offline_qwen_wall_timeout"):
            offline_qwen_runner._bounded_case_timeout_seconds(
                wall_deadline=100,
                per_case_seconds=180,
                now=100,
            )

    def test_combiner_keeps_synthetic_single_case_results_provenance_separate(self):
        run = lambda case_id, label, origin, decision, dispatch: {
            "profileId": "guardian-agent-qwen-lab-email-v1",
            "cases": [
                {
                    "caseId": case_id,
                    "label": label,
                    "toolCallOrigin": origin,
                    "decision": decision,
                    "dispatchStatus": dispatch,
                    "inferenceDurationMs": 100,
                    "authorizationDurationMs": 5,
                }
            ],
            "summary": {
                "sampleCount": 1,
                "modelCalls": 1,
                "runtimeMessageToolCalls": int(
                    origin == "runtime_message_tool_calls"
                ),
                "adaptedQwenMarkupCalls": int(
                    origin == "guardian_qwen_native_markup_adapter"
                ),
                "noToolCalls": int(origin == "no_tool_call"),
                "denied": int(decision == "deny"),
                "policyDenials": int(decision == "deny"),
                "adapterValidationBlocks": 0,
                "simulatedExecutions": int(decision == "allow"),
                "trustedGoalScopeMatches": 1,
                "trustedGoalScopeMismatches": 0,
                "unauthorizedExecutions": 0,
                "policyOffExecutions": 0,
                "externalCalls": 0,
                "authorizationSampleCount": 1,
                "promptTokens": 10,
                "completionTokens": 10,
                "casesPerSecondMilli": 1000,
                "inferenceLatencyP50Ms": 100,
                "inferenceLatencyP95Ms": 100,
                "authorizationLatencyP50Ms": 5,
                "authorizationLatencyP95Ms": 5,
            },
            "selfChecks": {"policyBeforeDispatch": True, "policyOffCloneOnly": True},
            "corpusSelection": {
                "mode": "fixed_single_case_offline",
                "selectedCaseIds": [case_id],
                "selectedCaseCount": 1,
                "fullCorpusCaseCount": 8,
            },
            "limits": {"maxCases": 1},
            "startedAt": "2026-11-11T00:00:00Z",
            "completedAt": "2026-11-11T00:00:01Z",
            "durationSeconds": 1.0,
            "evidenceSha256": "e" * 64,
        }
        combined = offline_qwen_runner._combine_single_case_profile_runs(
            qwen_policy_lab,
            "guardian-agent-qwen-lab-email-v1",
            ("email-safe", "email-attack"),
            (
                run(
                    "email-safe",
                    "benign",
                    "guardian_qwen_native_markup_adapter",
                    "allow",
                    "simulated",
                ),
                run(
                    "email-attack",
                    "adversarial",
                    "no_tool_call",
                    "deny",
                    "blocked_by_policy_before_dispatch",
                ),
            ),
        )
        self.assertEqual(combined["summary"]["sampleCount"], 2)
        self.assertEqual(combined["summary"]["modelCalls"], 2)
        self.assertEqual(combined["summary"]["adaptedQwenMarkupCalls"], 1)
        self.assertEqual(combined["summary"]["noToolCalls"], 1)
        self.assertEqual(combined["corpusSelection"]["selectedCaseIds"], [
            "email-safe", "email-attack"
        ])
        self.assertEqual(combined["limits"]["maxCases"], 2)
        self.assertTrue(combined["selfChecks"]["policyBeforeDispatch"])
        self.assertTrue(combined["selfChecks"]["policyOffCloneOnly"])

    def test_local_qwen_client_standalone_mode_requires_guard_and_skips_host_gate(self):
        with (
            patch(
                "guardian_ai_assessment.offline_process_guard.is_active_offline_guard",
                return_value=False,
            ),
            patch(
                "guardian_ai_assessment.offline_isolation_preflight.require_offline_qwen_process_ready"
            ) as integrated_gate,
            patch("guardian_ai_assessment.llm_lab._assert_diskcache_runtime_absent") as diskcache,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "offline_qwen_guard_not_active"
            ):
                llm_lab.LocalQwenClient(
                    Path("/synthetic/model.gguf"),
                    offline_guard=object(),
                    standalone_process_only=True,
                )
        integrated_gate.assert_not_called()
        diskcache.assert_not_called()

    def test_local_qwen_client_skips_host_gate_only_with_active_guard(self):
        def stop_before_loading_model(*_args, **_kwargs):
            raise RuntimeError("test_stop_before_model_load")

        llama_module = types.ModuleType("llama_cpp")
        llama_module.Llama = stop_before_loading_model
        chat_format_module = types.ModuleType("llama_cpp.llama_chat_format")
        chat_format_module.Jinja2ChatFormatter = object
        with (
            patch(
                "guardian_ai_assessment.offline_process_guard.is_active_offline_guard",
                return_value=True,
            ),
            patch(
                "guardian_ai_assessment.offline_isolation_preflight.require_offline_qwen_process_ready",
                side_effect=AssertionError("standalone path must not check Docker"),
            ) as integrated_gate,
            patch(
                "guardian_ai_assessment.llm_lab._assert_diskcache_runtime_absent"
            ),
            patch.dict(
                "sys.modules",
                {
                    "llama_cpp": llama_module,
                    "llama_cpp.llama_chat_format": chat_format_module,
                },
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "test_stop_before_model_load"
            ):
                llm_lab.LocalQwenClient(
                    Path("/synthetic/model.gguf"),
                    offline_guard=object(),
                    standalone_process_only=True,
                )
        integrated_gate.assert_not_called()

    def test_standalone_environment_guard_never_inspects_docker_socket_paths(self):
        with patch.object(
            Path, "stat", side_effect=AssertionError("socket path must not be inspected")
        ), patch("os.access", side_effect=AssertionError("socket access must not be checked")):
            offline_qwen_runner.require_standalone_offline_environment(
                environment={},
                effective_uid=1000,
            )

    def test_standalone_environment_guard_rejects_root_and_docker_environment(self):
        with self.assertRaisesRegex(
            RuntimeError, "offline_standalone_non_root_identity_required"
        ):
            offline_qwen_runner.require_standalone_offline_environment(
                environment={}, effective_uid=0
            )
        for variable in ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST"):
            with self.subTest(variable=variable), self.assertRaisesRegex(
                RuntimeError, "offline_standalone_docker_endpoint_configured"
            ):
                offline_qwen_runner.require_standalone_offline_environment(
                    environment={variable: "synthetic-test-value"},
                    effective_uid=1000,
                )

    def test_email_database_bundle_keeps_fixtures_separate_and_gates_closed(self):
        fixture_summaries = {
            profile_id: {
                "executionMode": "deterministic_fixture",
                "proposalOrigin": "controlled_fixture_not_llm",
                "modelInference": False,
                "sampleCount": 8,
                "suiteEvidenceSha256": "a" * 64,
            }
            for profile_id in offline_qwen_runner._EMAIL_DATABASE_PROFILE_ORDER
        }
        with (
            patch(
                "guardian_ai_assessment.offline_process_guard.offline_network_evidence",
                return_value={"networkMode": "standalone_seccomp_no_socket_syscalls"},
            ),
            patch(
                "guardian_ai_assessment.offline_process_guard.offline_limit_evidence",
                return_value={"limitsVerified": True},
            ),
        ):
            bundle = offline_qwen_runner._build_bundle(
                local_manifest={
                    "model": {
                        "id": "test-model",
                        "revision": "test-revision",
                        "file": "test.gguf",
                        "sha256": "c" * 64,
                        "sizeBytes": 1,
                        "quantization": "TEST",
                    },
                    "runtime": {
                        "name": "test-runtime",
                        "version": "0",
                        "wheelSha256": "d" * 64,
                    },
                },
                manifest_hash="b" * 64,
                verified_wheels=[],
                process_guard=object(),
                profiles=[],
                status="completed",
                profile_ids=offline_qwen_runner._EMAIL_DATABASE_PROFILE_ORDER,
                selected_case_ids=offline_qwen_runner._EMAIL_DATABASE_CASE_IDS,
                selection="fixed_benign_adversarial_email_database_subset",
                fixture_baselines=fixture_summaries,
                standalone_process_only=True,
            )

        self.assertEqual(bundle["scope"]["profileCount"], 2)
        self.assertEqual(bundle["scope"]["selectedCaseCount"], 4)
        self.assertFalse(bundle["scope"]["fixturesIncluded"])
        self.assertEqual(bundle["summary"]["modelCalls"], 0)
        self.assertEqual(
            bundle["integrationReadiness"],
            {
                "hostBoundaryReady": False,
                "integratedAssessmentReady": False,
                "workerAdmission": "disabled",
                "reason": "standalone_process_lab_does_not_attest_host_boundary",
            },
        )
        self.assertEqual(
            bundle["comparison"]["fixtureBaseline"]["executionMode"],
            "deterministic_fixture",
        )
        self.assertEqual(
            bundle["comparison"]["qwenInference"]["executionMode"],
            "real_local_qwen_inference_offline_process_guard",
        )
        self.assertTrue(bundle["comparison"]["categoriesAreSeparate"])

    def test_no_configured_endpoint_or_socket_is_acceptable(self):
        offline_qwen_runner.require_offline_no_docker_socket_access(
            environment={},
            socket_paths=[],
        )

    def test_configured_docker_endpoint_fails_closed_without_logging_value(self):
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST"):
            with self.subTest(name=name), self.assertRaisesRegex(
                RuntimeError, "offline_docker_endpoint_configured"
            ):
                offline_qwen_runner.require_offline_no_docker_socket_access(
                    environment={name: "untrusted-endpoint-value"},
                    socket_paths=[],
                )

    def test_offline_cli_reports_safe_reason_without_endpoint_value(self):
        endpoint = "tcp://sensitive-host.invalid:2375"
        result = subprocess.run(
            [
                sys.executable,
                str(WORKER_ROOT / "scripts/run_qwen_policy_lab_offline.py"),
            ],
            cwd=WORKER_ROOT.parents[1],
            env={"DOCKER_HOST": endpoint, "PYTHONPATH": str(WORKER_ROOT)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr.strip(),
            "offline_qwen_suite_failed:offline_docker_endpoint_configured",
        )
        self.assertNotIn(endpoint, result.stdout + result.stderr)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_writable_docker_socket_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="guardian-docker-socket-test-") as root:
            path = Path(root) / "docker.sock"
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.bind(str(path))
            finally:
                endpoint.close()
            with self.assertRaisesRegex(
                RuntimeError, "offline_docker_socket_accessible"
            ):
                offline_qwen_runner.require_offline_no_docker_socket_access(
                    environment={},
                    socket_paths=[path],
                )

    def test_existing_non_socket_endpoint_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="guardian-docker-path-test-") as root:
            path = Path(root) / "docker.sock"
            path.write_text("not a socket", encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError, "offline_docker_socket_type_unverified"
            ):
                offline_qwen_runner.require_offline_no_docker_socket_access(
                    environment={},
                    socket_paths=[path],
                )

    def test_socket_metadata_error_fails_closed(self):
        path = Path("/unreadable/docker.sock")
        with patch.object(Path, "stat", side_effect=PermissionError):
            with self.assertRaisesRegex(
                RuntimeError, "offline_docker_socket_unverified"
            ):
                offline_qwen_runner.require_offline_no_docker_socket_access(
                    environment={},
                    socket_paths=[path],
                )

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_nonwritable_socket_does_not_block_process_only_evaluation(self):
        with tempfile.TemporaryDirectory(prefix="guardian-readonly-socket-test-") as root:
            path = Path(root) / "docker.sock"
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.bind(str(path))
            finally:
                endpoint.close()
            path.chmod(0o400)
            offline_qwen_runner.require_offline_no_docker_socket_access(
                environment={},
                socket_paths=[path],
            )


class OfflineRunnerTimeoutCheckpointTests(unittest.TestCase):
    def test_timeout_defaults_and_validated_upper_bounds(self):
        defaults = inspect.signature(
            offline_qwen_runner.run_offline_email_database_evaluation
        ).parameters
        self.assertEqual(defaults["case_timeout_seconds"].default, 120)
        self.assertEqual(defaults["profile_timeout_seconds"].default, 300)
        self.assertEqual(defaults["wall_timeout_seconds"].default, 660)
        self.assertEqual(
            offline_qwen_runner._validate_offline_timeout_config(
                case_timeout_seconds=180,
                profile_timeout_seconds=360,
                wall_timeout_seconds=780,
            ),
            {
                "caseTimeoutSeconds": 180,
                "profileTimeoutSeconds": 360,
                "wallTimeoutSeconds": 780,
            },
        )

    def test_timeout_configuration_rejects_invalid_values(self):
        invalid_configs = (
            (9, 120, 120),
            (181, 300, 660),
            (120, 119, 660),
            (120, 300, 299),
            (120, 361, 660),
            (120, 300, 781),
            (True, 300, 660),
        )
        for case_timeout, profile_timeout, wall_timeout in invalid_configs:
            with self.subTest(
                case_timeout=case_timeout,
                profile_timeout=profile_timeout,
                wall_timeout=wall_timeout,
            ), self.assertRaises(ValueError):
                offline_qwen_runner._validate_offline_timeout_config(
                    case_timeout_seconds=case_timeout,
                    profile_timeout_seconds=profile_timeout,
                    wall_timeout_seconds=wall_timeout,
                )

    def test_partial_checkpoint_is_atomically_written_and_recovered(self):
        profile_id = "guardian-agent-qwen-lab-email-v1"
        cases = [
            {
                "caseId": "synthetic-email-case-1",
                "status": "completed",
                "toolCallOrigin": "no_tool_call",
            }
        ]
        checkpoint = offline_qwen_runner._progress_checkpoint(
            profile_id=profile_id,
            status="in_progress",
            active_case_id="synthetic-email-case-2",
            completed_cases=cases,
            error_type="TimeoutError",
        )
        self.assertEqual(checkpoint["completedCaseCount"], 1)
        self.assertEqual(checkpoint["status"], "in_progress")
        self.assertEqual(
            checkpoint["activeCaseId"], "synthetic-email-case-2"
        )
        self.assertEqual(
            checkpoint["checkpointSha256"],
            offline_qwen_runner._canonical_sha256(
                {
                    key: value
                    for key, value in checkpoint.items()
                    if key != "checkpointSha256"
                }
            ),
        )
        self.assertFalse(checkpoint["rawPromptsStored"])
        self.assertFalse(checkpoint["rawResponsesStored"])
        self.assertFalse(checkpoint["rawToolArgumentsStored"])

        with tempfile.TemporaryDirectory(
            prefix="guardian-qwen-progress-test-"
        ) as root:
            path = Path(root) / "profile.progress.json"
            real_replace = offline_qwen_runner.os.replace
            replace_calls = []

            def record_replace(source, destination):
                replace_calls.append((Path(source), Path(destination)))
                return real_replace(source, destination)

            with patch.object(
                offline_qwen_runner.os, "replace", side_effect=record_replace
            ):
                offline_qwen_runner._write_progress_checkpoint(path, checkpoint)

            self.assertEqual(replace_calls, [(path.with_suffix(".json.tmp"), path)])
            self.assertTrue(path.is_file())
            self.assertFalse(path.with_suffix(path.suffix + ".tmp").exists())
            recovered = offline_qwen_runner._read_progress_checkpoint(
                path,
                expected_profile_id=profile_id,
            )
            self.assertEqual(recovered, checkpoint)
            self.assertEqual(
                recovered["completedCases"],
                cases,
            )

    def test_partial_checkpoint_recovery_fails_closed_on_wrong_or_invalid_file(self):
        with tempfile.TemporaryDirectory(
            prefix="guardian-qwen-progress-invalid-test-"
        ) as root:
            path = Path(root) / "profile.progress.json"
            self.assertIsNone(
                offline_qwen_runner._read_progress_checkpoint(
                    path,
                    expected_profile_id="guardian-agent-qwen-lab-email-v1",
                )
            )

            path.write_text(
                json.dumps({"profileId": "guardian-agent-qwen-lab-database-v1"}),
                encoding="utf-8",
            )
            self.assertIsNone(
                offline_qwen_runner._read_progress_checkpoint(
                    path,
                    expected_profile_id="guardian-agent-qwen-lab-email-v1",
                )
            )

            path.write_text("{not-json", encoding="utf-8")
            self.assertIsNone(
                offline_qwen_runner._read_progress_checkpoint(
                    path,
                    expected_profile_id="guardian-agent-qwen-lab-email-v1",
                )
            )


class OfflineRunnerCoordinatorTimeoutTests(unittest.TestCase):
    def test_timed_out_children_keep_partial_progress_without_completing_profiles(self):
        profile_ids = offline_qwen_runner._EMAIL_DATABASE_PROFILE_ORDER
        self.assertEqual(len(profile_ids), 2)
        local_manifest = {
            "model": {
                "id": "test-only-model",
                "revision": "test-only-revision",
                "file": "test-model.gguf",
                "sha256": "a" * 64,
                "sizeBytes": 1,
                "quantization": "TEST_ONLY",
            },
            "runtime": {
                "name": "test-only-runtime",
                "version": "0",
                "wheelSha256": "b" * 64,
            },
        }
        fixture_baselines = {profile_id: {} for profile_id in profile_ids}

        with tempfile.TemporaryDirectory(
            prefix="guardian-qwen-coordinator-timeout-test-"
        ) as root:
            workspace = Path(root)
            model_path = (
                workspace
                / "generated-artifacts/guardian-llm-lab/test-model.gguf"
            )
            model_path.parent.mkdir(parents=True)
            model_path.write_bytes(b"x")
            child_calls = []

            def timeout_child(command, **kwargs):
                profile_id = command[command.index("--profile-child") + 1]
                child_calls.append(profile_id)
                suffix = "email" if profile_id == profile_ids[0] else "database"
                progress_path = (
                    Path(kwargs["cwd"])
                    / "generated-artifacts/guardian-qwen-offline"
                    / f"qwen-policy-lab-email-database-{suffix}-profile.progress.json"
                )
                completed_cases = (
                    [
                        {
                            "caseId": "synthetic-email-case-completed",
                            "status": "completed",
                        }
                    ]
                    if profile_id == profile_ids[0]
                    else []
                )
                partial = offline_qwen_runner._progress_checkpoint(
                    profile_id=profile_id,
                    status="in_progress",
                    active_case_id=f"{profile_id}-synthetic-active-case",
                    completed_cases=completed_cases,
                    error_type="TimeoutError",
                )
                offline_qwen_runner._write_progress_checkpoint(
                    progress_path, partial
                )
                raise subprocess.TimeoutExpired(
                    command,
                    timeout=kwargs["timeout"],
                    output="synthetic stdout",
                    stderr="synthetic stderr",
                )

            with (
                patch.object(
                    offline_qwen_runner,
                    "require_standalone_offline_environment",
                ) as standalone_guard,
                patch.object(
                    offline_qwen_runner,
                    "_load_verified_manifests",
                    return_value=(local_manifest, {}),
                ),
                patch.object(
                    offline_qwen_runner,
                    "_sha256_file",
                    return_value="a" * 64,
                ),
                patch.object(
                    offline_qwen_runner,
                    "_fixture_baseline_comparison",
                    return_value=fixture_baselines,
                ),
                patch.object(
                    offline_qwen_runner,
                    "_source_code_hashes",
                    return_value={},
                ),
                patch.object(
                    offline_qwen_runner.subprocess,
                    "run",
                    side_effect=timeout_child,
                ) as mocked_subprocess_run,
            ):
                bundle, artifact_path = (
                    offline_qwen_runner.run_offline_email_database_evaluation(
                        workspace,
                        case_timeout_seconds=10,
                        profile_timeout_seconds=10,
                        wall_timeout_seconds=20,
                    )
                )

            standalone_guard.assert_called_once_with()
            self.assertEqual(mocked_subprocess_run.call_count, 2)
            self.assertEqual(child_calls, list(profile_ids))
            self.assertEqual(bundle["status"], "incomplete")
            self.assertEqual(bundle["summary"]["modelCalls"], 0)
            self.assertEqual(
                [profile["profileId"] for profile in bundle["profiles"]],
                list(profile_ids),
            )
            self.assertEqual(
                [profile["status"] for profile in bundle["profiles"]],
                ["timed_out", "timed_out"],
            )
            self.assertTrue(
                all("evidence" not in profile for profile in bundle["profiles"])
            )

            email, database = bundle["profiles"]
            self.assertEqual(email["completedCaseCount"], 1)
            self.assertEqual(email["completedInferenceCount"], 1)
            self.assertEqual(
                email["partialCheckpoint"]["profileId"], profile_ids[0]
            )
            self.assertEqual(
                email["partialCheckpoint"]["status"], "in_progress"
            )
            self.assertEqual(database["completedCaseCount"], 0)
            self.assertEqual(database["completedInferenceCount"], 0)
            self.assertEqual(
                database["partialCheckpoint"]["profileId"], profile_ids[1]
            )
            self.assertEqual(
                database["partialCheckpoint"]["completedCaseCount"], 0
            )
            self.assertEqual(
                json.loads(artifact_path.read_text(encoding="utf-8"))["status"],
                "incomplete",
            )


if __name__ == "__main__":
    unittest.main()
