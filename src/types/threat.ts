export type AttackCategory = 'Normal' | 'DoS' | 'Probe' | 'R2L' | 'U2R';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface MITRETechnique {
  id: string; // e.g. T1059
  name: string; // e.g. Command and Scripting Interpreter
  tactic: string; // e.g. Execution
  description: string;
  associatedCategory?: AttackCategory;
  keywords: string[];
}

export interface MITREMatch {
  technique_id: string;
  name: string;
  tactic: string;
  score: number; // 0 to 1 cosine similarity
}

export interface ExtractedIOCs {
  ips: string[];
  domains: string[];
  hashes: string[];
  cves: string[];
}

export interface RawNSLKDDFeatures {
  duration: number;
  protocol_type: 'tcp' | 'udp' | 'icmp';
  service: string;
  flag: string;
  src_bytes: number;
  dst_bytes: number;
  land: number;
  wrong_fragment: number;
  urgent: number;
  hot: number;
  num_failed_logins: number;
  logged_in: number;
  num_compromised: number;
  root_shell: number;
  su_attempted: number;
  num_root: number;
  num_file_creations: number;
  num_shells: number;
  num_access_files: number;
  is_guest_login: number;
  count: number;
  srv_count: number;
  serror_rate: number;
  srv_serror_rate: number;
  rerror_rate: number;
  srv_rerror_rate: number;
  same_srv_rate: number;
  diff_srv_rate: number;
  srv_diff_host_rate: number;
  dst_host_count: number;
  dst_host_srv_count: number;
  dst_host_same_srv_rate: number;
  dst_host_diff_srv_rate: number;
  dst_host_same_src_port_rate: number;
  dst_host_srv_diff_host_rate: number;
  dst_host_serror_rate: number;
  dst_host_srv_serror_rate: number;
  dst_host_rerror_rate: number;
  dst_host_srv_rerror_rate: number;
}

export interface ScoredEvent {
  event_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  country: string;
  country_code: string;
  lat: number;
  lon: number;
  destination_asset: string;
  asset_criticality: number; // 0.1 to 1.0 (lookup: db 0.9, auth 0.95, gateway 0.8, workstation 0.5)
  attack_prob: number; // 0.0 to 1.0 (Random Forest)
  anomaly_score: number; // 0.0 to 1.0 (Isolation Forest)
  baseline_flag: 0 | 1; // Rule-based baseline (1 if flag triggered)
  attack_category: AttackCategory;
  specific_attack?: string; // e.g. neptune, smurf, satan, buffer_overflow, guess_passwd
  severity: number; // DoS 0.9, U2R 1.0, R2L 0.8, Probe 0.5, Normal 0
  risk_score: number; // 0 to 100
  risk_level: RiskLevel;
  mitre_technique: {
    id: string;
    name: string;
    tactic: string;
  };
  recommended_action: string;
  raw_features: RawNSLKDDFeatures;
}

export interface ModelMetrics {
  name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number; // false positive rate
  description: string;
}

export interface ConfusionMatrixData {
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
}

export interface FeatureImportanceItem {
  feature: string;
  importance: number;
  description: string;
}

export interface SettingsConfig {
  weight_attack_prob: number; // default 0.5
  weight_severity: number; // default 0.3
  weight_asset_criticality: number; // default 0.2
  threshold_low_to_med: number; // 25
  threshold_med_to_high: number; // 50
  threshold_high_to_crit: number; // 75
  mitre_similarity_threshold: number; // 0.30
}

export interface ThreatReport {
  id: string;
  title: string;
  source: string;
  date: string;
  category: string;
  text: string;
  expectedIocs?: Partial<ExtractedIOCs>;
}
