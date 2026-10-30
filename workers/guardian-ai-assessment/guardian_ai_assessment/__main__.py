from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
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
    if interfaces != ["lo"]:
        raise RuntimeError("network_interfaces_not_loopback_only")

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

    if _probe_public_socket(socket.AF_INET, PUBLIC_IPV4, 443):
        raise RuntimeError("public_ipv4_reachable")

    if socket.has_ipv6 and _probe_public_socket(
        socket.AF_INET6, PUBLIC_IPV6, 443
    ):
        raise RuntimeError("public_ipv6_reachable")

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
        "publicIpv4": "blocked",
        "publicIpv6": "blocked",
        "publicDns": "blocked",
        "loopbackOnly": True,
    }


def verify_loopback_agent() -> None:
    with socket.create_connection((AGENT_HOST, AGENT_PORT), timeout=1) as client:
        client.sendall(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        reply = client.recv(512)
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
    return {
        "reportSha256": hashlib.sha256(raw).hexdigest(),
        "reportRecords": len(lines),
        "reportBytes": len(raw),
    }


def run_assessment() -> dict[str, Any]:
    installed_version = importlib.metadata.version("garak")
    if installed_version != ENGINE_VERSION:
        raise RuntimeError("garak_version_mismatch")
    if os.geteuid() == 0:
        raise RuntimeError("worker_must_not_run_as_root")

    network_evidence = verify_network_isolation()
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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=MAX_RUNTIME_SECONDS,
                check=False,
                close_fds=True,
            )
            if completed.returncode != 0:
                raise RuntimeError("garak_execution_failed")

            report_files = sorted(temp_path.glob("*.report.jsonl"))
            if len(report_files) != 1:
                raise RuntimeError("garak_report_missing_or_ambiguous")
            report_evidence = _parse_report(report_files[0])
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
                "reportRecordCount": report_evidence["reportRecords"],
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
                "findings": [],
                "findingSummary": "Limited probe execution; not a security guarantee.",
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
