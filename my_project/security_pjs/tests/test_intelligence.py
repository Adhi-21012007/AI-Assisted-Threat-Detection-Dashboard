import os
import sqlite3
import struct
import unittest

from security_pjs.dashboard_data import event_detail, intelligence_records, record_action
from security_pjs.intelligence import analyse_email, analyse_ip, analyse_pcap, analyse_qr, analyse_url, generate_report, parse_nmap_xml, persist_finding
from security_pjs.tests.test_pipeline import make_db


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.path = make_db()
        con = sqlite3.connect(self.path)
        for column in ("name TEXT", "designation TEXT", "status TEXT"):
            con.execute("ALTER TABLE employees ADD COLUMN " + column)
        con.close()

    def tearDown(self):
        os.unlink(self.path)

    def test_url_ip_email_and_vt_fallback(self):
        url = analyse_url("http://login.verify.account.example.zip/secure?redirect=x")
        self.assertGreaterEqual(url["risk_score"], 40)
        self.assertFalse(url["external"]["available"])
        ip = analyse_ip("10.55.0.8", self.path)
        self.assertEqual(ip["ip_type"], "Private")
        email = analyse_email("Urgent verify account", "mail@example.com", "user@example.com", "Verify your password immediately at http://login.verify.example.zip", "Reply-To: other@different.example")
        self.assertGreaterEqual(email["risk_score"], 40)

    def test_imported_nmap_pcap_and_qr_safe_states(self):
        nmap = parse_nmap_xml(b'<nmaprun><host><address addr="10.0.0.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host></nmaprun>')
        self.assertEqual(nmap["analysis_mode"], "IMPORTED AUTHORISED NMAP RESULT")
        self.assertGreater(nmap["risk_score"], 0)
        # Global header plus one Ethernet/IPv4/TCP frame (no live capture involved).
        header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1)
        packet = b"\x00" * 12 + b"\x08\x00" + bytes([0x45]) + b"\x00" * 8 + bytes([6]) + b"\x00" * 2 + bytes([10,0,0,1,10,0,0,2]) + struct.pack("!HH", 50000, 23)
        capture = header + struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet
        pcap = analyse_pcap(capture)
        self.assertEqual(pcap["analysis_mode"], "UPLOADED CAPTURE ANALYSIS")
        qr = analyse_qr(b"not an image", "invalid.png")
        self.assertIn("QR", qr["analysis_mode"])

    def test_persistence_correlation_report_and_false_positive(self):
        result = analyse_url("http://login.verify.account.example.zip")
        stored = persist_finding(self.path, "URL_ANALYSIS", "URL_ANALYZER", result, "admin", employee_id="EMP001")
        self.assertTrue(stored["security_event_id"])
        self.assertTrue(intelligence_records(self.path, "URL_ANALYSIS"))
        detail = event_detail(self.path, stored["security_event_id"])
        record_action(self.path, detail["id"], "FALSE_POSITIVE", "Known training URL", "admin")
        self.assertEqual(event_detail(self.path, detail["id"])["incident_status"], "FALSE POSITIVE")
        report = generate_report(self.path, "URL Analysis Report", stored["security_event_id"], "admin")
        self.assertEqual(report["source"], "URL_ANALYZER")


if __name__ == "__main__":
    unittest.main(verbosity=2)
