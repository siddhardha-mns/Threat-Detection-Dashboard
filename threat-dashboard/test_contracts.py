"""
SOC Threat Intelligence Dashboard - Contract Validation Test Suite
Executes with standard library Python (3.8+) to verify that all functional contracts
from Section 4 of the Implementation Document behave as specified.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.risk_engine import risk_score, risk_level, DEFAULT_RISK_CONFIG
from src.baseline import baseline_predict_single
from src.geo import lookup_ip
from src.nlp_engine import extract_iocs


class TestThreatContracts(unittest.TestCase):

    def test_risk_score_calculation(self):
        """Verify Section 4 composite risk formula:
        Risk = (w_ml * P_ml + w_anom * S_anom + w_asset * C_asset + w_geo * G_geo + w_ti * T_ti) * 100
        Default weights: 0.35, 0.20, 0.20, 0.15, 0.10
        """
        row = {
            "ml_prob": 1.0,
            "anomaly_score": 1.0,
            "asset_criticality": 1.0,
            "geo_risk": 1.0,
            "threat_intel_match": 1.0
        }
        score = risk_score(row)
        self.assertAlmostEqual(score, 100.0, places=1)

        row_half = {
            "ml_prob": 0.5,
            "anomaly_score": 0.5,
            "asset_criticality": 0.5,
            "geo_risk": 0.5,
            "threat_intel_match": 0.5
        }
        self.assertAlmostEqual(risk_score(row_half), 50.0, places=1)

        row_zero = {
            "ml_prob": 0.0,
            "anomaly_score": 0.0,
            "asset_criticality": 0.0,
            "geo_risk": 0.0,
            "threat_intel_match": 0.0
        }
        self.assertEqual(risk_score(row_zero), 0.0)

    def test_risk_level_thresholds(self):
        """Verify risk tiers:
        >= 80 -> CRITICAL
        >= 60 -> HIGH
        >= 40 -> MEDIUM
        < 40  -> LOW
        """
        self.assertEqual(risk_level(95), "CRITICAL")
        self.assertEqual(risk_level(80), "CRITICAL")
        self.assertEqual(risk_level(79.9), "HIGH")
        self.assertEqual(risk_level(60), "HIGH")
        self.assertEqual(risk_level(59.9), "MEDIUM")
        self.assertEqual(risk_level(40), "MEDIUM")
        self.assertEqual(risk_level(39.9), "LOW")
        self.assertEqual(risk_level(0), "LOW")

    def test_ioc_extraction(self):
        """Verify regex extraction for IPv4, domains, hashes, and CVEs."""
        sample_text = """
        Incident Alert: Detected beaconing from internal host 192.168.1.55 to C2 server 185.220.101.45.
        Target contacted malicious domain evil-c2-beacon.ru and staging host update-cdn.net.
        Dropped payload MD5: 5d41402abc4b2a76b9719d911017c592
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Suspected exploitation of CVE-2021-44228 and CVE-2023-38606.
        """
        iocs = extract_iocs(sample_text)

        # Check IPs
        self.assertIn("192.168.1.55", iocs["ips"])
        self.assertIn("185.220.101.45", iocs["ips"])

        # Check Domains
        self.assertIn("evil-c2-beacon.ru", iocs["domains"])
        self.assertIn("update-cdn.net", iocs["domains"])

        # Check Hashes
        self.assertIn("5d41402abc4b2a76b9719d911017c592", iocs["hashes"])
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", iocs["hashes"])

        # Check CVEs
        self.assertIn("CVE-2021-44228", iocs["cves"])
        self.assertIn("CVE-2023-38606", iocs["cves"])

    def test_baseline_predict_single(self):
        """Verify rule-based baseline logic on attack patterns."""
        # SYN flood pattern: high count and high serror_rate
        dos_row = {
            "count": 450,
            "serror_rate": 0.95,
            "same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_bytes": 0,
            "src_bytes": 0,
            "num_failed_logins": 0
        }
        pred_dos, prob_dos = baseline_predict_single(dos_row)
        self.assertEqual(pred_dos, 1)
        self.assertGreaterEqual(prob_dos, 0.8)

        # Normal benign traffic
        normal_row = {
            "count": 5,
            "serror_rate": 0.0,
            "same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.05,
            "dst_bytes": 4500,
            "src_bytes": 1200,
            "num_failed_logins": 0
        }
        pred_norm, prob_norm = baseline_predict_single(normal_row)
        self.assertEqual(pred_norm, 0)
        self.assertLess(prob_norm, 0.4)

    def test_ip_geolocation_resolution(self):
        """Verify geo lookup returns valid lat/long coordinates and risk."""
        geo_info = lookup_ip("185.220.101.5")
        self.assertIn("country", geo_info)
        self.assertIn("lat", geo_info)
        self.assertIn("lon", geo_info)
        self.assertIn("risk_factor", geo_info)
        self.assertIsInstance(geo_info["lat"], (int, float))
        self.assertIsInstance(geo_info["lon"], (int, float))
        self.assertGreaterEqual(geo_info["risk_factor"], 0.0)
        self.assertLessEqual(geo_info["risk_factor"], 1.0)


if __name__ == "__main__":
    unittest.main()
