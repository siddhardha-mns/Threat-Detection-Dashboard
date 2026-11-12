"""
nlp_engine.py - Member B (NLP & Risk)
Regex IOC extraction and semantic mapping to MITRE ATT&CK techniques.
"""
import re
import csv
import os
from typing import Dict, List, Any

IPV4_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b'
HASH_REGEX = r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b'
CVE_REGEX = r'CVE-\d{4}-\d{4,7}'

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Deduplicates and returns extracted IOCs in dict with keys:
    ips, domains, hashes, cves.
    """
    if not text:
        return {'ips': [], 'domains': [], 'hashes': [], 'cves': []}

    ips = list(set(re.findall(IPV4_REGEX, text)))
    valid_ips = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split('.'))]

    raw_domains = re.findall(DOMAIN_REGEX, text.lower())
    valid_domains = list(set(
        d for d in raw_domains 
        if not re.match(r'^\d+(\.\d+)+$', d) and '.' in d and len(d.split('.')[-1]) >= 2
    ))

    hashes = list(set(h.lower() for h in re.findall(HASH_REGEX, text)))
    cves = list(set(c.upper() for c in re.findall(CVE_REGEX, text, re.IGNORECASE)))

    return {
        'ips': sorted(valid_ips),
        'domains': sorted(valid_domains),
        'hashes': sorted(hashes),
        'cves': sorted(cves)
    }

def load_mitre_techniques(csv_path="data/mitre/techniques.csv") -> List[Dict[str, str]]:
    techniques = []
    # Try relative to current script
    full_path = os.path.join(os.path.dirname(__file__), "..", csv_path)
    target = full_path if os.path.exists(full_path) else csv_path
    if os.path.exists(target):
        with open(target, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                techniques.append(row)
    return techniques

def map_mitre(text: str, top_k: int = 3, threshold: float = 0.15) -> List[Dict[str, Any]]:
    """
    Maps text to MITRE techniques using token semantic overlap & cosine similarity.
    Returns list of dicts with keys: id, name, tactic, similarity, description.
    """
    techniques = load_mitre_techniques()
    if not techniques:
        # Fallback default techniques
        techniques = [
            {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'description': 'PowerShell bash script cmd shell execution process launch'},
            {'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access', 'description': 'email attachment invoice lure link spearphishing credential harvest'},
            {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access', 'description': 'ssh password spraying dictionary guess credentials unauthorized attempt'},
            {'id': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery', 'description': 'port scan nmap probe sweep syn reconnaissance syn flood sweep'},
            {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact', 'description': 'syn flood smurf teardrop dos crash exhaustion buffer overflow'},
            {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'description': 'cve exploit web vulnerability rce unpatched apache sql injection log4j'},
            {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'description': 'c2 beacon http https dns tunneling exfiltration web service communication'},
            {'id': 'T1021', 'name': 'Remote Services', 'tactic': 'Lateral Movement', 'description': 'rdp smb ssh lateral movement remote desktop windows admin share'},
            {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact', 'description': 'ransomware encryption shadow copy vssadmin decrypt bitcoin extortion'},
            {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'description': 'compromised credentials default account stolen token privilege abuse'}
        ]

    tokens_input = set(re.findall(r'\b[a-z0-9_-]{3,}\b', text.lower()))
    matches = []

    for t in techniques:
        tid = t.get('id') or t.get('technique_id', 'T1000')
        desc = (t.get('description', '') + ' ' + t.get('name', '') + ' ' + t.get('tactic', '') + ' ' + t.get('keywords', '')).lower()
        t_tokens = set(re.findall(r'\b[a-z0-9_-]{3,}\b', desc))
        
        intersection = tokens_input.intersection(t_tokens)
        if not t_tokens or not tokens_input:
            sim = 0.0
        else:
            sim = (2.0 * len(intersection)) / (len(tokens_input) + len(t_tokens))
            sim = min(1.0, sim * 2.5) # scale for overlap

        if sim >= threshold or len(intersection) >= 2:
            matches.append({
                'id': tid,
                'technique_id': tid,
                'name': t.get('name', 'Technique'),
                'tactic': t.get('tactic', 'Defense Evasion'),
                'similarity': round(float(min(0.99, max(0.1, sim))), 2),
                'score': round(float(sim), 2),
                'description': t.get('description', '')
            })

    matches.sort(key=lambda x: x['similarity'], reverse=True)
    return matches[:top_k]

def score_report_text(text: str) -> Dict[str, Any]:
    """
    Computes summary threat score for an unstructured incident report.
    """
    iocs = extract_iocs(text)
    techniques = map_mitre(text, top_k=3)

    ioc_weight = min(40.0, len(iocs['ips']) * 5 + len(iocs['hashes']) * 10 + len(iocs['cves']) * 15 + len(iocs['domains']) * 5)
    technique_weight = (techniques[0]['similarity'] * 40.0) if techniques else 10.0
    critical_keywords = ['ransomware', 'exploit', 'exfiltration', 'lateral movement', 'c2', 'beacon', 'unauthorized', 'rootkit', 'zeroday']
    kw_hits = sum(1 for kw in critical_keywords if kw in text.lower())
    keyword_weight = min(20.0, kw_hits * 5.0)

    total_score = round(min(100.0, ioc_weight + technique_weight + keyword_weight), 1)
    level = "CRITICAL" if total_score >= 80 else ("HIGH" if total_score >= 60 else ("MEDIUM" if total_score >= 40 else "LOW"))

    return {
        "risk_score": total_score,
        "risk_level": level,
        "iocs": iocs,
        "techniques": techniques
    }
