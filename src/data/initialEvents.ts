import { ScoredEvent, AttackCategory } from '../types/threat';
import {
  calculateRiskScore,
  DEFAULT_SETTINGS,
  getRiskLevel,
  predictIsolationForestAnomaly,
  predictRandomForestProb,
  recommendAction,
  SEVERITY_BY_CATEGORY,
} from '../engine/scoringEngine';

interface GeoLocation {
  country: string;
  country_code: string;
  lat: number;
  lon: number;
}

const GLOBAL_GEO_LOCATIONS: GeoLocation[] = [
  { country: 'United States', country_code: 'US', lat: 37.7749, lon: -122.4194 },
  { country: 'China', country_code: 'CN', lat: 39.9042, lon: 116.4074 },
  { country: 'Russia', country_code: 'RU', lat: 55.7558, lon: 37.6173 },
  { country: 'Germany', country_code: 'DE', lat: 52.52, lon: 13.405 },
  { country: 'United Kingdom', country_code: 'GB', lat: 51.5074, lon: -0.1278 },
  { country: 'Brazil', country_code: 'BR', lat: -23.5505, lon: -46.6333 },
  { country: 'Netherlands', country_code: 'NL', lat: 52.3676, lon: 4.9041 },
  { country: 'India', country_code: 'IN', lat: 28.6139, lon: 77.209 },
  { country: 'North Korea', country_code: 'KP', lat: 39.0392, lon: 125.7625 },
  { country: 'Iran', country_code: 'IR', lat: 35.6892, lon: 51.389 },
  { country: 'France', country_code: 'FR', lat: 48.8566, lon: 2.3522 },
  { country: 'Japan', country_code: 'JP', lat: 35.6762, lon: 139.6503 },
  { country: 'Australia', country_code: 'AU', lat: -33.8688, lon: 151.2093 },
  { country: 'Ukraine', country_code: 'UA', lat: 50.4501, lon: 30.5234 },
  { country: 'Romania', country_code: 'RO', lat: 44.4268, lon: 26.1025 },
];

const DESTINATION_ASSETS = [
  { name: 'db-prod-cluster-01.internal', criticality: 0.95 },
  { name: 'auth-ldap-primary.corp', criticality: 0.95 },
  { name: 'fin-swift-gateway-02.lan', criticality: 0.9 },
  { name: 'api-ingress-edge.dmz', criticality: 0.85 },
  { name: 'pki-vault-ca.prod', criticality: 0.95 },
  { name: 'k8s-master-node-03.cloud', criticality: 0.8 },
  { name: 'payment-processor-core.dmz', criticality: 0.95 },
  { name: 'corp-mail-exchange.dmz', criticality: 0.75 },
  { name: 'eng-git-server.internal', criticality: 0.7 },
  { name: 'dev-workstation-88.office', criticality: 0.5 },
  { name: 'hr-workstation-12.office', criticality: 0.5 },
  { name: 'guest-wifi-ap-04.corp', criticality: 0.3 },
];

const ATTACK_DISTRIBUTIONS: {
  category: AttackCategory;
  specific: string;
  protocol: 'tcp' | 'udp' | 'icmp';
  service: string;
  mitre: { id: string; name: string; tactic: string };
  weight: number;
}[] = [
  {
    category: 'DoS',
    specific: 'neptune',
    protocol: 'tcp',
    service: 'http',
    mitre: { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact' },
    weight: 25,
  },
  {
    category: 'DoS',
    specific: 'smurf',
    protocol: 'icmp',
    service: 'eco_i',
    mitre: { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact' },
    weight: 15,
  },
  {
    category: 'Probe',
    specific: 'satan',
    protocol: 'tcp',
    service: 'private',
    mitre: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
    weight: 20,
  },
  {
    category: 'Probe',
    specific: 'portsweep',
    protocol: 'tcp',
    service: 'domain_u',
    mitre: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
    weight: 15,
  },
  {
    category: 'R2L',
    specific: 'guess_passwd',
    protocol: 'tcp',
    service: 'ssh',
    mitre: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    weight: 15,
  },
  {
    category: 'R2L',
    specific: 'warezmaster',
    protocol: 'tcp',
    service: 'ftp',
    mitre: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    weight: 10,
  },
  {
    category: 'U2R',
    specific: 'buffer_overflow',
    protocol: 'tcp',
    service: 'telnet',
    mitre: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    weight: 5,
  },
  {
    category: 'U2R',
    specific: 'rootkit',
    protocol: 'tcp',
    service: 'smtp',
    mitre: { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
    weight: 4,
  },
  {
    category: 'Normal',
    specific: 'normal',
    protocol: 'tcp',
    service: 'http',
    mitre: { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion, Persistence' },
    weight: 40,
  },
];

function pseudoRandom(seed: number) {
  const x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

export function generateSyntheticEvents(count = 160, startSeed = 42): ScoredEvent[] {
  const events: ScoredEvent[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const seed = startSeed + i * 17.38;
    const rand1 = pseudoRandom(seed);
    const rand2 = pseudoRandom(seed + 1);
    const rand3 = pseudoRandom(seed + 2);
    const rand4 = pseudoRandom(seed + 3);
    const rand5 = pseudoRandom(seed + 4);

    // Pick attack template
    const attackIdx = Math.floor(rand1 * ATTACK_DISTRIBUTIONS.length);
    const template = ATTACK_DISTRIBUTIONS[attackIdx];

    const geo = GLOBAL_GEO_LOCATIONS[Math.floor(rand2 * GLOBAL_GEO_LOCATIONS.length)];
    const asset = DESTINATION_ASSETS[Math.floor(rand3 * DESTINATION_ASSETS.length)];

    // Generate realistic IPs
    const octet1 = Math.floor(rand1 * 200) + 20;
    const octet2 = Math.floor(rand2 * 254) + 1;
    const octet3 = Math.floor(rand3 * 254) + 1;
    const octet4 = Math.floor(rand4 * 254) + 1;
    const srcIp = `${octet1}.${octet2}.${octet3}.${octet4}`;
    const dstIp = `10.140.${Math.floor(rand5 * 30) + 10}.${Math.floor(rand2 * 250) + 1}`;

    // Timestamp spanning the past 24 hours
    const minutesAgo = Math.floor(rand4 * 1440);
    const eventTime = new Date(now - minutesAgo * 60 * 1000).toISOString();

    const isAttack = template.category !== 'Normal';

    // Raw NSL-KDD features
    const srcBytes = isAttack
      ? template.category === 'DoS' ? Math.floor(rand1 * 50) : Math.floor(rand1 * 35000) + 8000
      : Math.floor(rand1 * 1200) + 200;

    const dstBytes = isAttack
      ? template.category === 'DoS' ? 0 : Math.floor(rand2 * 24000)
      : Math.floor(rand2 * 4500) + 500;

    const countVal = isAttack && template.category === 'DoS'
      ? Math.floor(rand3 * 280) + 110
      : Math.floor(rand3 * 50) + 2;

    const serrorRate = isAttack && template.category === 'DoS'
      ? Math.round((0.7 + rand4 * 0.3) * 100) / 100
      : Math.round((rand4 * 0.08) * 100) / 100;

    const rawFeatures = {
      duration: isAttack ? Math.floor(rand5 * 40) : Math.floor(rand5 * 5),
      protocol_type: template.protocol,
      service: template.service,
      flag: isAttack && template.category === 'DoS' ? 'S0' : 'SF',
      src_bytes: srcBytes,
      dst_bytes: dstBytes,
      land: 0,
      wrong_fragment: template.category === 'DoS' && rand2 > 0.7 ? 1 : 0,
      urgent: 0,
      hot: template.category === 'R2L' ? Math.floor(rand3 * 4) + 1 : 0,
      num_failed_logins: template.category === 'R2L' ? Math.floor(rand4 * 5) + 1 : 0,
      logged_in: isAttack && template.category === 'U2R' ? 1 : isAttack ? 0 : 1,
      num_compromised: template.category === 'U2R' ? 1 : 0,
      root_shell: template.category === 'U2R' ? 1 : 0,
      su_attempted: template.category === 'U2R' && rand1 > 0.5 ? 1 : 0,
      num_root: template.category === 'U2R' ? Math.floor(rand2 * 3) + 1 : 0,
      num_file_creations: template.category === 'U2R' ? 2 : 0,
      num_shells: template.category === 'U2R' ? 1 : 0,
      num_access_files: 0,
      is_guest_login: template.category === 'R2L' && rand3 > 0.6 ? 1 : 0,
      count: countVal,
      srv_count: Math.floor(countVal * 0.8) + 1,
      serror_rate: serrorRate,
      srv_serror_rate: serrorRate,
      rerror_rate: template.category === 'Probe' ? 0.85 : 0.0,
      srv_rerror_rate: template.category === 'Probe' ? 0.82 : 0.0,
      same_srv_rate: isAttack && template.category === 'Probe' ? 0.05 : 0.95,
      diff_srv_rate: isAttack && template.category === 'Probe' ? 0.92 : 0.04,
      srv_diff_host_rate: 0.0,
      dst_host_count: 255,
      dst_host_srv_count: isAttack ? 12 : 230,
      dst_host_same_srv_rate: isAttack ? 0.06 : 0.92,
      dst_host_diff_srv_rate: isAttack ? 0.88 : 0.03,
      dst_host_same_src_port_rate: isAttack ? 0.75 : 0.01,
      dst_host_srv_diff_host_rate: 0.0,
      dst_host_serror_rate: serrorRate,
      dst_host_srv_serror_rate: serrorRate,
      dst_host_rerror_rate: template.category === 'Probe' ? 0.8 : 0.0,
      dst_host_srv_rerror_rate: template.category === 'Probe' ? 0.78 : 0.0,
    };

    // Calculate ML models
    const attackProb = predictRandomForestProb(rawFeatures, template.category);
    const anomalyScore = predictIsolationForestAnomaly(rawFeatures, template.category);
    const baselineFlag = (rawFeatures.count > 100 || rawFeatures.src_bytes > 10000 || rawFeatures.serror_rate > 0.5) ? 1 : 0;
    const severity = SEVERITY_BY_CATEGORY[template.category];

    const riskScore = calculateRiskScore(attackProb, severity, asset.criticality, DEFAULT_SETTINGS);
    const riskLevel = getRiskLevel(riskScore, DEFAULT_SETTINGS);

    events.push({
      event_id: `EVT-${(10000 + i).toString()}`,
      timestamp: eventTime,
      src_ip: srcIp,
      dst_ip: dstIp,
      country: geo.country,
      country_code: geo.country_code,
      lat: geo.lat + (rand1 - 0.5) * 4,
      lon: geo.lon + (rand2 - 0.5) * 4,
      destination_asset: asset.name,
      asset_criticality: asset.criticality,
      attack_prob: attackProb,
      anomaly_score: anomalyScore,
      baseline_flag: baselineFlag,
      attack_category: template.category,
      specific_attack: template.specific,
      severity: severity,
      risk_score: riskScore,
      risk_level: riskLevel,
      mitre_technique: template.mitre,
      recommended_action: recommendAction(riskLevel, template.category),
      raw_features: rawFeatures,
    });
  }

  // Sort descending by timestamp
  return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export const INITIAL_SCORED_EVENTS = generateSyntheticEvents(160, 101);
