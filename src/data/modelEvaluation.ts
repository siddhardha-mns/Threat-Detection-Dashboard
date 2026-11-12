import { ModelMetrics, FeatureImportanceItem, ConfusionMatrixData } from '../types/threat';

export const MODEL_COMPARISON_METRICS: ModelMetrics[] = [
  {
    name: 'Random Forest (Supervised)',
    accuracy: 0.992,
    precision: 0.988,
    recall: 0.995,
    f1: 0.991,
    fpr: 0.009, // 0.9% FPR
    description: 'Trained on 41 NSL-KDD features (n_estimators=200, class_weight=balanced). Highest overall accuracy and lowest false-positive rate on known attack families.',
  },
  {
    name: 'Isolation Forest (Anomaly)',
    accuracy: 0.914,
    precision: 0.892,
    recall: 0.938,
    f1: 0.914,
    fpr: 0.082, // 8.2% FPR
    description: 'Unsupervised anomaly detector fit on normal traffic distribution only. Uniquely flags zero-day and unseen protocol variations that evasion attacks attempt.',
  },
  {
    name: 'Rule-Based Baseline (SIEM)',
    accuracy: 0.825,
    precision: 0.694,
    recall: 0.781,
    f1: 0.735,
    fpr: 0.287, // 28.7% FPR - massive analyst fatigue!
    description: 'Legacy fixed threshold rules (count > 100 OR src_bytes > 10000 OR serror_rate > 0.5). High false-positive rate overwhelms SOC operations.',
  },
];

export const CONFUSION_MATRIX: ConfusionMatrixData = {
  truePositive: 12762,
  falsePositive: 114,
  trueNegative: 9597,
  falseNegative: 68,
};

export const ROC_CURVES = {
  rf: [
    { fpr: 0.000, tpr: 0.000 },
    { fpr: 0.002, tpr: 0.840 },
    { fpr: 0.005, tpr: 0.950 },
    { fpr: 0.009, tpr: 0.995 },
    { fpr: 0.020, tpr: 0.998 },
    { fpr: 0.050, tpr: 0.999 },
    { fpr: 0.100, tpr: 1.000 },
    { fpr: 1.000, tpr: 1.000 },
  ],
  if: [
    { fpr: 0.000, tpr: 0.000 },
    { fpr: 0.020, tpr: 0.610 },
    { fpr: 0.050, tpr: 0.810 },
    { fpr: 0.082, tpr: 0.938 },
    { fpr: 0.150, tpr: 0.965 },
    { fpr: 0.300, tpr: 0.985 },
    { fpr: 0.600, tpr: 0.995 },
    { fpr: 1.000, tpr: 1.000 },
  ],
  baseline: [
    { fpr: 0.000, tpr: 0.000 },
    { fpr: 0.100, tpr: 0.350 },
    { fpr: 0.200, tpr: 0.600 },
    { fpr: 0.287, tpr: 0.781 },
    { fpr: 0.450, tpr: 0.850 },
    { fpr: 0.700, tpr: 0.920 },
    { fpr: 1.000, tpr: 1.000 },
  ],
  auc: {
    rf: 0.996,
    if: 0.924,
    baseline: 0.768,
  },
};

export const FEATURE_IMPORTANCES: FeatureImportanceItem[] = [
  { feature: 'src_bytes', importance: 0.224, description: 'Number of data bytes from source to destination' },
  { feature: 'dst_bytes', importance: 0.178, description: 'Number of data bytes from destination to source' },
  { feature: 'serror_rate', importance: 0.119, description: '% of connections that have SYN errors' },
  { feature: 'same_srv_rate', importance: 0.096, description: '% of connections to the same service' },
  { feature: 'count', importance: 0.088, description: 'Number of connections to same host in past 2 seconds' },
  { feature: 'dst_host_srv_count', importance: 0.075, description: 'Number of connections to same service across destination hosts' },
  { feature: 'flag', importance: 0.064, description: 'Status flag of connection (e.g. S0, REJ, SF)' },
  { feature: 'dst_host_serror_rate', importance: 0.052, description: '% of connections having SYN errors on destination host' },
  { feature: 'logged_in', importance: 0.043, description: '1 if successfully logged in; 0 otherwise' },
  { feature: 'diff_srv_rate', importance: 0.038, description: '% of connections to different services' },
];
