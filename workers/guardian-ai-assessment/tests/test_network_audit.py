import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from guardian_ai_assessment.network_audit import (
    build_network_audit,
    probe_ipv6_dns,
)


class NetworkAuditTests(unittest.TestCase):
    def test_ipv6_dns_reports_kernel_protocol_unavailable(self):
        with patch(
            "guardian_ai_assessment.network_audit.socket.socket",
            side_effect=OSError(errno.EAFNOSUPPORT, "IPv6 unavailable"),
        ):
            self.assertEqual(probe_ipv6_dns(), "unavailable")

    def test_ipv6_dns_reports_blocked_only_when_kernel_denies_route(self):
        fake_socket = MagicMock()
        fake_socket.sendto.side_effect = OSError(
            errno.ENETUNREACH, "no route"
        )
        with patch(
            "guardian_ai_assessment.network_audit.socket.socket",
            return_value=fake_socket,
        ):
            self.assertEqual(probe_ipv6_dns(), "blocked")
        fake_socket.close.assert_called_once()

    def test_sent_dns_without_response_is_not_reported_as_blocked(self):
        fake_socket = MagicMock()
        fake_socket.sendto.return_value = 48
        fake_socket.recvfrom.side_effect = socket.timeout()
        with patch(
            "guardian_ai_assessment.network_audit.socket.socket",
            return_value=fake_socket,
        ):
            self.assertEqual(probe_ipv6_dns(), "sent_no_response")

    def test_unavailable_ipv6_is_incomplete_not_a_pass(self):
        base = {
            "networkMode": "docker-network-none",
            "publicIpv4": "blocked",
            "publicDns": "blocked",
            "publicIpv6": "unavailable",
            "ipv6Capability": "kernel_protocol_unavailable",
            "activeNonLoopbackInterfaces": [],
            "loopbackOnly": True,
        }
        with (
            patch(
                "guardian_ai_assessment.network_audit.probe_ipv6_dns",
                return_value="unavailable",
            ),
            patch(
                "guardian_ai_assessment.network_audit.probe_loopback",
                side_effect=["reachable", "unavailable"],
            ),
        ):
            result = build_network_audit(base)
        self.assertEqual(result["overall"], "incomplete_ipv6_not_verified")
        self.assertEqual(result["ipv6PublicTcp"], "unavailable")
        self.assertEqual(result["ipv6DnsRoute"], "unavailable")

    def test_complete_denials_and_loopback_pass(self):
        base = {
            "networkMode": "docker-network-none",
            "publicIpv4": "blocked",
            "publicDns": "blocked",
            "publicIpv6": "blocked",
            "ipv6Capability": "socket_and_route_tested",
            "activeNonLoopbackInterfaces": [],
            "loopbackOnly": True,
        }
        with (
            patch(
                "guardian_ai_assessment.network_audit.probe_ipv6_dns",
                return_value="blocked",
            ),
            patch(
                "guardian_ai_assessment.network_audit.probe_loopback",
                return_value="reachable",
            ),
        ):
            result = build_network_audit(base)
        self.assertEqual(result["overall"], "verified")

    def test_reachable_ipv6_dns_route_fails_closed(self):
        base = {
            "networkMode": "docker-network-none",
            "publicIpv4": "blocked",
            "publicDns": "blocked",
            "publicIpv6": "blocked",
            "ipv6Capability": "socket_and_route_tested",
            "activeNonLoopbackInterfaces": [],
            "loopbackOnly": True,
        }
        with (
            patch(
                "guardian_ai_assessment.network_audit.probe_ipv6_dns",
                return_value="reachable",
            ),
            patch(
                "guardian_ai_assessment.network_audit.probe_loopback",
                return_value="reachable",
            ),
        ):
            result = build_network_audit(base)
        self.assertEqual(result["overall"], "failed")


if __name__ == "__main__":
    unittest.main()
