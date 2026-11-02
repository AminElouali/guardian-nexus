"""Extended, read-only checks for the isolated Docker worker network."""

from __future__ import annotations

import errno
import json
import socket
import sys
from typing import Any

from .__main__ import _dns_query_packet, verify_network_isolation

_NO_ROUTE_ERRNOS = {
    errno.ENETDOWN,
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
}
_NO_IPV6_ERRNOS = {
    errno.EAFNOSUPPORT,
    errno.EPROTONOSUPPORT,
}
_NO_IPV4_ERRNOS = {
    errno.EAFNOSUPPORT,
    errno.EPROTONOSUPPORT,
}
_DOC_IPV4_UDP = "192.0.2.53"
_DOC_IPV6_DNS = "2001:db8::53"
_DOC_IPV6_UDP = "2001:db8::53"


def _probe_udp(family: int, address: str, port: int, payload: bytes) -> str:
    """Classify a UDP probe; lack of a reply is not proof of network blocking."""
    try:
        client = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as exc:
        unavailable_errnos = _NO_IPV6_ERRNOS if family == socket.AF_INET6 else _NO_IPV4_ERRNOS
        return "unavailable" if exc.errno in unavailable_errnos else f"error:{exc.errno}"

    try:
        client.settimeout(0.5)
        try:
            client.sendto(payload, (address, port))
        except socket.timeout:
            return "timeout_on_send"
        except OSError as exc:
            unavailable_errnos = _NO_IPV6_ERRNOS if family == socket.AF_INET6 else _NO_IPV4_ERRNOS
            if exc.errno in unavailable_errnos:
                return "unavailable"
            if exc.errno in _NO_ROUTE_ERRNOS:
                return "blocked"
            return f"error:{exc.errno}"
        try:
            client.recvfrom(512)
        except socket.timeout:
            return "timeout_no_response"
        except OSError as exc:
            if exc.errno in _NO_ROUTE_ERRNOS:
                return "blocked"
            return f"error:{exc.errno}"
        return "reachable"
    finally:
        client.close()


def probe_ipv4_udp() -> str:
    """Probe only RFC 5737 TEST-NET-1; it is never a real public service."""
    return _probe_udp(
        socket.AF_INET,
        _DOC_IPV4_UDP,
        65000,
        b"guardian-nexus-udp-egress-check",
    )


def probe_ipv6_udp() -> str:
    """Probe only the reserved IPv6 documentation prefix."""
    return _probe_udp(
        socket.AF_INET6,
        _DOC_IPV6_UDP,
        65000,
        b"guardian-nexus-udp-egress-check",
    )


def probe_ipv6_dns() -> str:
    """Send a single synthetic DNS query only to the reserved documentation prefix."""
    return _probe_udp(
        socket.AF_INET6,
        _DOC_IPV6_DNS,
        53,
        _dns_query_packet("guardian-nexus.invalid"),
    )


def probe_loopback(family: int, address: str) -> str:
    """Verify a TCP listener and client can communicate only on loopback."""
    try:
        server = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        return (
            "unavailable"
            if family == socket.AF_INET6 and exc.errno in _NO_IPV6_ERRNOS
            else f"error:{exc.errno}"
        )

    try:
        server.settimeout(0.5)
        server.bind((address, 0))
        server.listen(1)
        endpoint = server.getsockname()
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(endpoint)
            connection, _ = server.accept()
            with connection:
                client.sendall(b"loopback-check")
                if connection.recv(32) != b"loopback-check":
                    return "error:loopback_payload_mismatch"
        return "reachable"
    except OSError as exc:
        return f"error:{exc.errno}"
    finally:
        server.close()


def build_network_audit(base: dict[str, Any]) -> dict[str, Any]:
    ipv6_status = base.get("publicIpv6")
    udp4 = probe_ipv4_udp()
    udp6 = probe_ipv6_udp() if ipv6_status != "unavailable" else "unavailable"
    dns6 = probe_ipv6_dns() if ipv6_status != "unavailable" else "unavailable"
    loop4 = probe_loopback(socket.AF_INET, "127.0.0.1")
    loop6 = (
        probe_loopback(socket.AF_INET6, "::1")
        if ipv6_status != "unavailable"
        else "unavailable"
    )
    statuses = (
        base.get("publicIpv4"),
        udp4,
        base.get("publicDns"),
        ipv6_status,
        udp6,
        dns6,
        loop4,
        loop6,
    )
    if (
        base.get("loopbackOnly") is True
        and statuses
        == (
            "blocked",
            "blocked",
            "blocked",
            "blocked",
            "blocked",
            "blocked",
            "reachable",
            "reachable",
        )
    ):
        overall = "verified"
    elif "unavailable" in statuses:
        overall = (
            "incomplete_ipv6_not_verified"
            if ipv6_status == "unavailable"
            else "incomplete_protocol_not_verified"
        )
    else:
        overall = "failed"

    return {
        "schemaVersion": 1,
        "overall": overall,
        "networkMode": base.get("networkMode"),
        "ipv4PublicTcp": base.get("publicIpv4"),
        "ipv4PublicUdp": udp4,
        "ipv4DnsUdp": base.get("publicDns"),
        "ipv6Capability": base.get("ipv6Capability"),
        "ipv6PublicTcp": ipv6_status,
        "ipv6PublicUdp": udp6,
        "ipv6DnsRoute": dns6,
        "loopbackIpv4": loop4,
        "loopbackIpv6": loop6,
        "activeNonLoopbackInterfaces": base.get("activeNonLoopbackInterfaces"),
        "noPersistentChanges": True,
        "note": (
            "IPv6 unavailable is not evidence of blocked IPv6 egress."
            if overall == "incomplete_ipv6_not_verified"
            else (
                "UDP timeouts are not treated as proof of blocking. UDP probes target "
                "documentation-only address ranges."
            )
        ),
    }


def run_network_audit() -> dict[str, Any]:
    # The existing preflight rejects active non-loopback interfaces and default
    # routes before it attempts any external-address probes.
    return build_network_audit(verify_network_isolation())


def main() -> int:
    try:
        result = run_network_audit()
    except Exception as exc:
        print(
            json.dumps(
                {"schemaVersion": 1, "overall": "failed", "error": str(exc)},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    if result["overall"] == "verified":
        return 0
    if result["overall"] == "incomplete_ipv6_not_verified":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
