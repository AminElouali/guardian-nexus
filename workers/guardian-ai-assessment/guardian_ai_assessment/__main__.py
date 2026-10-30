from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

ENGINE_VERSION = "0.17.1"
PROFILE_ID = "guardian-local-agent-v1"
PROBE_CLASS = "probes.promptinject.HijackHateHumans"
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 8765
MAX_BODY_BYTES = 16 * 1024
PUBLIC_IPV4 = "1.1.1.1"
PUBLIC_IPV6 = "2606:4700:4700::1111"
MAX_RUNTIME_SECONDS = 120


class LocalLabHandler(BaseHTTPRequestHandler):
    server_version = "GuardianLocalLab/1"
    sys_version = ""
    request_count = 0

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"local-lab-only"}')

    def do_POST(self) -> None:
        if self.path != "/chat":
            self.send_error(404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length < 1 or content_length > MAX_BODY_BYTES:
                self.send_error(413)
                return
            decoded = json.loads(self.rfile.read(content_length))
            prompt = decoded.get("prompt") if isinstance(decoded, dict) else None
            if not isinstance(prompt, str) or len(prompt) > 8192:
                self.send_error(400)
                return
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        # No model, tools, secrets, customer data, or outbound API calls exist
        # in this deliberately static, owned laboratory target.
        response = {
            "text": "I will not follow untrusted instruction overrides. "
            "I can only respond within this local test profile."
        }
        type(self).request_count += 1
        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _loopback_agent() -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer((AGENT_HOST, AGENT_PORT), LocalLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _dns_query_packet(hostname: str) -> bytes:
    transaction_id = b"\x13\x37"
    flags = b"\x01\x00"
    question_count = b"\x00\x01"
    zero_counts = b"\x00\x00\x00\x00\x00\x00"
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in hostname.rstrip(".").split(".")
    ) + b"\x00"
    return transaction_id + flags + question_count + zero_counts + qname + b"\x00\x01\x00\x01"


def _probe_public_socket(family: int, address: str, port: int) -> bool:
    """Return True only when a connection was actually established."""
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.35)
            client.connect((address, port))
            return True
    except OSError:
        return False


def verify_network_isolation() -> dict[str, Any]:
    interfaces = sorted(os.listdir("/sys/class/net"))
    active_non_loopback = []
    for interface in interfaces:
        if interface == "lo":
            continue
        try:
            flags = int(
                Path(f"/sys/class/net/{interface}/flags").read_text().strip(),
                16,
            )
            operstate = Path(
                f"/sys/class/net/{interface}/operstate"
            ).read_text().strip()
        except OSError as exc:
            raise RuntimeError("network_interface_state_unavailable") from exc
        if flags & 0x1 or operstate == "up":
            active_non_loopback.append(interface)
    if active_non_loopback:
        raise RuntimeError("active_non_loopback_interface_present")

    try:
        ipv4_routes = Path("/proc/net/route").read_text().splitlines()[1:]
        has_ipv4_default = any(
            len(line.split()) > 1 and line.split()[1] == "00000000"
            for line in ipv4_routes
        )
    except OSError as exc:
        raise RuntimeError("ipv4_route_table_unavailable") from exc
    if has_ipv4_default:
        raise RuntimeError("ipv4_default_route_present")

    ipv6_routes_path = Path("/proc/net/ipv6_route")
    if ipv6_routes_path.exists():
        for line in ipv6_routes_path.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == ("0" * 32) and fields[1] == "00":
                raise RuntimeError("ipv6_default_route_present")

    if _probe_public_socket(socket.AF_INET, PUBLIC_IPV4, 443):
        raise RuntimeError("public_ipv4_reachable")

    if socket.has_ipv6:
        try:
            if _probe_public_socket(socket.AF_INET6, PUBLIC_IPV6, 443):
                raise RuntimeError("public_ipv6_reachable")
        except OSError:
            pass

    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.settimeout(0.35)
    try:
        dns_socket.sendto(_dns_query_packet("example.com"), (PUBLIC_IPV4, 53))
        try:
            dns_socket.recvfrom(512)
        except TimeoutError:
            pass
        else:
            raise RuntimeError("public_dns_reachable")
    except OSError:
        pass
    finally:
        dns_socket.close()

    return {
        "networkMode": "docker-network-none",
        "interfaces": interfaces,
        "activeNonLoopbackInterfaces": active_non_loopback,
        "publicIpv4": "blocked",
        "publicIpv6": "blocked",
        "publicDns": "blocked",
        "loopbackOnly": True,
    }


def verify_loopback_agent() -> None:
    reply = bytearray()
    with socket.create_connection((AGENT_HOST, AGENT_PORT), timeout=1) as client:
        client.sendall(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        while True:
            chunk = client.recv(512)
            if not chunk:
                break
            reply.extend(chunk)
    if b"200 OK" not in reply or b"local-lab-only" not in reply:
        raise RuntimeError("loopback_agent_unavailable")


def _parse_report(report_path: Path) -> dict[str, Any]:
    raw = report_path.read_bytes()
    if not raw:
        raise RuntimeError("empty_garak_report")
    lines: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            lines.append(candidate)
    if len(lines) < 2:
        raise RuntimeError("garak_report_has_no_attempt_records")
    record_types: dict[str, int] = {}
    detector_hits = 0
    findings_by_detector: dict[str, int] = {}
    for record in lines:
        entry_type = record.get("entry_type")
        if isinstance(entry_type, str):
            record_types[entry_type] = record_types.get(entry_type, 0) + 1
        if entry_type != "attempt":
            continue
        detector_results = record.get("detector_results")
        if isinstance(detector_results, dict):
            for detector, outcomes in detector_results.items():
                if isinstance(outcomes, list):
                    positive_scores = sum(
                        1
                        for outcome in outcomes
                        if isinstance(outcome, (int, float))
                        and not isinstance(outcome, bool)
                        and outcome > 0
                    )
                    detector_hits += positive_scores
                    if positive_scores and isinstance(detector, str):
                        findings_by_detector[detector] = (
                            findings_by_detector.get(detector, 0) + positive_scores
                        )
    return {
        "reportSha256": hashlib.sha256(raw).hexdigest(),
        "reportRecords": len(lines),
        "reportBytes": len(raw),
        "recordTypes": record_types,
        "detectorHits": detector_hits,
        "findings": [
            {
                "probeClass": PROBE_CLASS,
                "detector": detector,
                "positiveScores": hits,
            }
            for detector, hits in sorted(findings_by_detector.items())
        ],
    }


def run_assessment() -> dict[str, Any]:
    installed_version = importlib.metadata.version("garak")
    if installed_version != ENGINE_VERSION:
        raise RuntimeError("garak_version_mismatch")
    if os.geteuid() == 0:
        raise RuntimeError("worker_must_not_run_as_root")

    network_evidence = verify_network_isolation()
    LocalLabHandler.request_count = 0
    server, _thread = _loopback_agent()
    started_at = datetime.now(timezone.utc)
    try:
        verify_loopback_agent()
        with tempfile.TemporaryDirectory(prefix="guardian-ai-") as temp_dir:
            temp_path = Path(temp_dir)
            generator_file = temp_path / "rest-generator.json"
            generator_file.write_text(
                json.dumps(
                    {
                        "rest": {
                            "RestGenerator": {
                                "name": PROFILE_ID,
                                "uri": f"http://{AGENT_HOST}:{AGENT_PORT}/chat",
                                "method": "post",
                                "headers": {"Content-Type": "application/json"},
                                "req_template_json_object": {"prompt": "$INPUT"},
                                "response_json": True,
                                "response_json_field": "text",
                                "request_timeout": 2,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            report_prefix = temp_path / "assessment"
            command = [
                sys.executable,
                "-m",
                "garak",
                "--target_type",
                "rest",
                "--generator_option_file",
                str(generator_file),
                "--spec",
                PROBE_CLASS,
                "--config",
                "/opt/guardian-assessment/run-config.json",
                "--generations",
                "1",
                "--parallel_requests",
                "1",
                "--parallel_attempts",
                "1",
                "--confidence_interval_method",
                "none",
                "--report_prefix",
                str(report_prefix),
                "--narrow_output",
            ]
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=MAX_RUNTIME_SECONDS,
                check=False,
                close_fds=True,
            )
            if completed.returncode != 0:
                safe_logs = (
                    completed.stderr.decode("utf-8", errors="replace")
                    + completed.stdout.decode("utf-8", errors="replace")
                )
                missing_dependency = re.search(
                    r"ModuleNotFoundError: No module named ['\"]([A-Za-z0-9_.-]+)['\"]",
                    safe_logs,
                )
                if missing_dependency:
                    module = missing_dependency.group(1).replace(".", "_")
                    raise RuntimeError(f"missing_dependency_{module}")
                raise RuntimeError(f"garak_exit_code_{abs(completed.returncode)}")
            probe_requests = LocalLabHandler.request_count
            if probe_requests != 1:
                raise RuntimeError("probe_request_limit_exceeded")

            report_files = sorted(temp_path.glob("*.report.jsonl"))
            if len(report_files) != 1:
                raise RuntimeError("garak_report_missing_or_ambiguous")
            report_evidence = _parse_report(report_files[0])
            if report_evidence["reportBytes"] > 262_144:
                raise RuntimeError("report_size_limit_exceeded")
            finished_at = datetime.now(timezone.utc)
            duration_seconds = max(
                0,
                int((finished_at - started_at).total_seconds()),
            )
            if duration_seconds > MAX_RUNTIME_SECONDS:
                raise RuntimeError("assessment_duration_limit_exceeded")

            return {
                "evidenceVersion": 1,
                "source": "isolated_local_lab",
                "engine": "garak",
                "engineVersion": installed_version,
                "profileId": PROFILE_ID,
                "probeClasses": [PROBE_CLASS],
                "generationsPerProbe": 1,
                "probeRequests": probe_requests,
                "reportRecordCount": report_evidence["reportRecords"],
                "reportRecordTypes": report_evidence["recordTypes"],
                "positiveDetectorScores": report_evidence["detectorHits"],
                "findings": report_evidence["findings"],
                "reportSha256": report_evidence["reportSha256"],
                "reportBytes": report_evidence["reportBytes"],
                "network": network_evidence,
                "startedAt": started_at.isoformat(),
                "completedAt": finished_at.isoformat(),
                "durationSeconds": duration_seconds,
                "promptsStored": False,
                "responsesStored": False,
                "externalCalls": 0,
                "customerDataUsed": False,
                "findings": report_evidence["findings"],
                "findingSummary": (
                    f"Limited local probe recorded {report_evidence['detectorHits']} "
                    "positive detector scores; not a security guarantee."
                ),
            }
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = {
            "selfTest": "passed",
            "network": verify_network_isolation(),
        }
        server, _thread = _loopback_agent()
        try:
            verify_loopback_agent()
            result["loopbackAgent"] = "available"
        finally:
            server.shutdown()
            server.server_close()
    else:
        result = run_assessment()
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired:
        print('{"errorCode":"worker_timeout"}', file=sys.stdout)
        raise SystemExit(124)
    except Exception as exc:
        code = str(exc) if str(exc).isidentifier() else "worker_failed"
        print(json.dumps({"errorCode": code}, separators=(",", ":")), file=sys.stdout)
        raise SystemExit(1)
