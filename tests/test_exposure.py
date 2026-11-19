import io
import ipaddress
import sys
import unittest
from unittest.mock import patch

from wardr import exposure


MAC_HEADER = (
    "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes rhiwat shiwat "
    "process:pid state options gencnt flags flags1 usecnt rtncnt fltrs\n"
)
LINUX_HEADER = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"


def _proc_address(address, port):
    packed = ipaddress.ip_address(address).packed
    words = [int.from_bytes(packed[index:index + 4], sys.byteorder) for index in range(0, len(packed), 4)]
    return "".join(f"{word:08X}" for word in words) + f":{port:04X}"


def _proc_row(address, port, remote, remote_port, state):
    return (
        f"  0: {_proc_address(address, port)} {_proc_address(remote, remote_port)} {state} "
        "00000000:00000000 00:00000000 00000000 1000 0 123 1 0000000000000000\n"
    )


class ExposureTests(unittest.TestCase):
    def test_mac_uses_listen_only_and_preserves_owner_name_with_spaces(self):
        output = MAC_HEADER + (
            "tcp46 0 0 *.8443 *.* LISTEN 0 0 0 0 Example Server:120 001 0 0 0 0 0 0 0\n"
            "tcp4 0 0 127.0.0.1.8843 127.0.0.1.1234 ESTABLISHED 0 0 0 0 Client:121 001 0 0 0 0 0 0 0\n"
        )
        endpoints, complete = exposure._parse_mac(output, "tcp")
        self.assertTrue(complete)
        self.assertEqual(endpoints, [{
            "protocol": "tcp", "address": "*", "port": 8443, "scope": "wildcard", "family": "dual",
            "pid": 120, "process": "Example Server",
        }])

    def test_mac_skips_connected_and_unbound_udp_sockets(self):
        output = MAC_HEADER + (
            "udp6 0 0 fe80::1%en0.5353 *.* 0 0 0 0 Example Discovery:122 001 0 0 0 0 0 0 0\n"
            "udp4 0 0 127.0.0.1.7777 127.0.0.1.1234 0 0 0 0 Client:123 001 0 0 0 0 0 0 0\n"
            "udp46 0 0 *.* *.* 0 0 0 0 Unbound:124 001 0 0 0 0 0 0 0\n"
        )
        endpoints, complete = exposure._parse_mac(output, "udp")
        self.assertTrue(complete)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["address"], "fe80::1%en0")
        self.assertEqual(endpoints[0]["scope"], "interface")

    def test_linux_ipv6_mapped_loopback_and_uid(self):
        stream = io.StringIO(
            LINUX_HEADER
            + _proc_row("::ffff:127.0.0.1", 9000, "::", 0, "0A")
            + _proc_row("::1", 9001, "::1", 9002, "01")
        )
        endpoints, complete = exposure._parse_linux(stream, "tcp", "ipv6")
        self.assertTrue(complete)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(
            endpoints[0],
            {
                "protocol": "tcp", "address": str(ipaddress.ip_address("::ffff:127.0.0.1")), "port": 9000,
                "scope": "loopback", "family": "ipv6", "uid": 1000,
            },
        )

    def test_linux_udp_only_counts_unconnected_bindings(self):
        stream = io.StringIO(
            LINUX_HEADER
            + _proc_row("0.0.0.0", 9000, "0.0.0.0", 0, "07")
            + _proc_row("127.0.0.1", 9001, "127.0.0.1", 9002, "01")
            + _proc_row("127.0.0.1", 9003, "127.0.0.1", 9002, "07")
        )
        endpoints, complete = exposure._parse_linux(stream, "udp", "ipv4")
        self.assertTrue(complete)
        self.assertEqual([item["scope"] for item in endpoints], ["wildcard"])

    def test_windows_retains_valid_rows_and_reports_partial_coverage(self):
        snapshot = {
            "tcp": [
                {"LocalAddress": "0.0.0.0", "LocalPort": 8443, "OwningProcess": 120},
                {"LocalAddress": "0.0.0.0", "LocalPort": 8443, "OwningProcess": 120},
                {"LocalAddress": "127.0.0.1", "LocalPort": 8444, "OwningProcess": 121},
                {"LocalAddress": "malformed"},
            ],
            "udp": None,
        }
        with (
            patch.object(exposure.platform, "system", return_value="Windows"),
            patch.object(exposure, "_windows_snapshot", return_value=exposure._parse_windows(snapshot)),
        ):
            collected = exposure.collect_exposure()
        self.assertEqual(collected["state"], "partial")
        self.assertEqual(collected["summary"], {"total": 2, "wildcard": 1, "interface": 0, "loopback": 1})
        self.assertEqual(collected["listeners"][0]["pid"], 120)
        self.assertTrue(all(not item["available"] for item in collected["coverage"]))
