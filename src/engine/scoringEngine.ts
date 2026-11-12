import {
  ExtractedIOCs,
  MITREMatch,
  RawNSLKDDFeatures,
  RiskLevel,
  ScoredEvent,
  SettingsConfig,
  AttackCategory,
} from '../types/threat';
import { MITRE_TECHNIQUES } from '../data/mitreTechniques';

export const DEFAULT_SETTINGS: SettingsConfig = {
  weight_attack_prob: 0.5,
  weight_severity: 0.3,
  weight_asset_criticality: 0.2,
  threshold_low_to_med: 25,
  threshold_med_to_high: 50,
  threshold_high_to_crit: 75,
  mitre_similarity_threshold: 0.3,
};

export const SEVERITY_BY_CATEGORY: Record<AttackCategory, number> = {
  Normal: 0.0,
  Probe: 0.5,
  R2L: 0.8,
  DoS: 0.9,
  U2R: 1.0,
};

// Regex patterns specified in Implementation Doc (Page 4, Step 2)
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_REGEX = /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi;
const HASH_REGEX = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/gi;

const COMMON_EXTENSIONS_EXCLUDE = new Set([
  'txt', 'pdf', 'csv', 'doc', 'docx', 'png', 'jpg', 'jpeg', 'zip', 'gz', 'tar', 'py', 'ts', 'js', 'html', 'css',
  'json', 'xml', 'exe', 'dll', 'sh', 'bat', 'com', 'org', 'net'
]);

export function extractIOCs(text: string): ExtractedIOCs {
  if (!text) return { ips: [], domains: [], hashes: [], cves: [] };

  // IPv4 extraction with octet boundary validation (0-255)
  const rawIps = text.match(IPV4_REGEX) || [];
  const validIps = Array.from(new Set(
    rawIps.filter((ip) => {
      const octets = ip.split('.').map(Number);
      return octets.length === 4 && octets.every((o) => o >= 0 && o <= 255);
    })
  ));

  // CVE extraction
  const rawCves = text.match(CVE_REGEX) || [];
  const validCves = Array.from(new Set(rawCves.map((c) => c.toUpperCase())));

  // Hashes extraction (MD5: 32, SHA1: 40, SHA256: 64)
  const rawHashes = text.match(HASH_REGEX) || [];
  const validHashes = Array.from(new Set(rawHashes.map((h) => h.toLowerCase())));

  // Domain extraction (filter out bare IPs, file extensions, and common false positives)
  const rawDomains = text.match(DOMAIN_REGEX) || [];
  const validDomains = Array.from(new Set(
    rawDomains
      .map((d) => d.toLowerCase())
      .filter((domain) => {
        if (/^\d+(\.\d+)+$/.test(domain)) return false; // is IP or decimal string
        const parts = domain.split('.');
        if (parts.length < 2) return false;
        const tld = parts[parts.length - 1];
        if (tld.length < 2 || tld.length > 10) return false;
        // Avoid simple file names
        if (parts.length === 2 && COMMON_EXTENSIONS_EXCLUDE.has(tld) && !['com', 'org', 'net', 'io', 'ai'].includes(tld)) {
          return false;
        }
        return true;
      })
  ));

  return {
    ips: validIps,
    domains: validDomains,
    hashes: validHashes,
    cves: validCves,
  };
}

// Tokenize text into words for semantic similarity scoring
function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s_-]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2);
}

// Cosine semantic similarity between threat report and MITRE technique descriptions
export function semanticMapMITRE(text: string, threshold = 0.3): MITREMatch[] {
  if (!text) return [];

  const textTokens = tokenize(text);
  const textFreq: Record<string, number> = {};
  for (const t of textTokens) {
    textFreq[t] = (textFreq[t] || 0) + 1;
  }

  const results: MITREMatch[] = [];

  for (const tech of MITRE_TECHNIQUES) {
    // Combine technique name, tactic, description, and curated keywords
    const techDoc = `${tech.name} ${tech.tactic} ${tech.description} ${tech.keywords.join(' ')}`;
    const techTokens = tokenize(techDoc);

    const techFreq: Record<string, number> = {};
    for (const t of techTokens) {
      techFreq[t] = (techFreq[t] || 0) + 1;
    }

    // Dot product and magnitudes
    let dotProduct = 0;
    for (const token of Object.keys(textFreq)) {
      if (techFreq[token]) {
        // Boost matches on specific key security identifiers
        const weight = tech.keywords.includes(token) ? 2.5 : 1.0;
        dotProduct += textFreq[token] * techFreq[token] * weight;
      }
    }

    const magA = Math.sqrt(Object.values(textFreq).reduce((sum, v) => sum + v * v, 0));
    const magB = Math.sqrt(Object.values(techFreq).reduce((sum, v) => sum + v * v, 0));

    let score = magA && magB ? dotProduct / (magA * magB) : 0;
    // Normalize and scale to reasonable 0-1 similarity representation
    score = Math.min(1.0, score * 1.6);

    if (score >= threshold) {
      results.push({
        technique_id: tech.id,
        name: tech.name,
        tactic: tech.tactic,
        score: Math.round(score * 100) / 100,
      });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, 3);
}

// Risk calculation formula from Implementation Doc (Page 5, Step 5)
// risk = 100 * (0.5 * attack_prob + 0.3 * severity + 0.2 * asset_criticality)
export function calculateRiskScore(
  attackProb: number,
  severity: number,
  assetCriticality: number,
  settings: SettingsConfig = DEFAULT_SETTINGS
): number {
  const rawScore =
    100 *
    (settings.weight_attack_prob * attackProb +
      settings.weight_severity * severity +
      settings.weight_asset_criticality * assetCriticality);

  return Math.min(100, Math.max(0, Math.round(rawScore * 10) / 10));
}

export function getRiskLevel(score: number, settings: SettingsConfig = DEFAULT_SETTINGS): RiskLevel {
  if (score < settings.threshold_low_to_med) return 'Low';
  if (score < settings.threshold_med_to_high) return 'Medium';
  if (score < settings.threshold_high_to_crit) return 'High';
  return 'Critical';
}

// Rule-based baseline detector from Implementation Doc (Page 3, Step 5)
// flag if count > 100 or src_bytes > 10000 or serror_rate > 0.5
export function evaluateRuleBaseline(features: RawNSLKDDFeatures): 0 | 1 {
  if (features.count > 100 || features.src_bytes > 10000 || features.serror_rate > 0.5) {
    return 1;
  }
  return 0;
}

// Emulate Random Forest probability based on NSL-KDD feature signatures
export function predictRandomForestProb(features: RawNSLKDDFeatures, category: AttackCategory): number {
  if (category === 'Normal') {
    // Small baseline noise for benign traffic (low false positive)
    return Math.max(0.01, Math.min(0.18, features.serror_rate * 0.15 + (features.count > 80 ? 0.08 : 0.02)));
  }

  let baseProb = 0.85;

  if (category === 'DoS') {
    if (features.count > 120 || features.serror_rate > 0.6) baseProb = 0.98;
    else if (features.src_bytes === 0 && features.dst_bytes === 0) baseProb = 0.95;
    else baseProb = 0.88;
  } else if (category === 'Probe') {
    if (features.rerror_rate > 0.5 || features.srv_rerror_rate > 0.5) baseProb = 0.93;
    else if (features.same_srv_rate < 0.2) baseProb = 0.91;
    else baseProb = 0.82;
  } else if (category === 'R2L') {
    if (features.num_failed_logins > 0 || features.is_guest_login === 1) baseProb = 0.96;
    else if (features.hot > 2) baseProb = 0.89;
    else baseProb = 0.84;
  } else if (category === 'U2R') {
    if (features.root_shell === 1 || features.su_attempted === 1 || features.num_root > 0) baseProb = 0.99;
    else baseProb = 0.92;
  }

  return Math.min(0.99, Math.max(0.72, baseProb));
}

// Emulate Isolation Forest anomaly score (0 to 1, higher = more anomalous)
export function predictIsolationForestAnomaly(features: RawNSLKDDFeatures, category: AttackCategory): number {
  // Outlier detection on feature space
  let score = 0.15;

  if (features.serror_rate > 0.4) score += 0.35;
  if (features.src_bytes > 20000 || features.dst_bytes > 30000) score += 0.25;
  if (features.diff_srv_rate > 0.6) score += 0.2;
  if (features.count > 150) score += 0.15;
  if (features.root_shell === 1 || features.num_failed_logins > 1) score += 0.3;

  if (category !== 'Normal') {
    score = Math.max(score, 0.74);
  }

  return Math.min(0.98, Math.max(0.04, Math.round(score * 100) / 100));
}

export function recommendAction(riskLevel: RiskLevel, category: AttackCategory): string {
  switch (riskLevel) {
    case 'Critical':
      return category === 'U2R'
        ? 'Isolate host immediately & revoke all enterprise root sessions'
        : 'Block source IP at edge perimeter firewall & drop active TCP states';
    case 'High':
      return category === 'DoS'
        ? 'Activate upstream rate limiting & blackhole attacking subnet'
        : 'Force multi-factor authentication reset & quarantine affected asset';
    case 'Medium':
      return 'Add IP to watchlist, collect full PCAP telemetry & notify SOC Tier 2';
    case 'Low':
    default:
      return 'Log event to SIEM index & monitor for repeat correlation';
  }
}
