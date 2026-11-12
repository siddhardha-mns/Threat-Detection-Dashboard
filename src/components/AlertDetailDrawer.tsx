import React, { useState } from 'react';
import { X, ShieldCheck, AlertTriangle, Copy, Check, ExternalLink, Cpu, Database, Activity, Ban } from 'lucide-react';
import { ScoredEvent } from '../types/threat';

interface AlertDetailDrawerProps {
  event: ScoredEvent | null;
  onClose: () => void;
  onBlockIp?: (ip: string) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({ event, onClose, onBlockIp }) => {
  const [copied, setCopied] = useState(false);
  const [blocked, setBlocked] = useState(false);

  if (!event) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleBlock = () => {
    if (onBlockIp) onBlockIp(event.src_ip);
    setBlocked(true);
    setTimeout(() => setBlocked(false), 3000);
  };

  const riskColor = {
    Critical: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    High: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    Medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    Low: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  }[event.risk_level];

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-full max-w-xl bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-5 border-b border-slate-800 bg-slate-950 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-slate-100">{event.event_id}</span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${riskColor}`}>
                {event.risk_level} ({event.risk_score}/100)
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              {new Date(event.timestamp).toLocaleString()} · {event.country}
            </p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs text-slate-300">
        {/* Recommended SOC Action Callout */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Recommended SOC Action
            </span>
            <button
              onClick={handleBlock}
              className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                blocked
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-rose-600 hover:bg-rose-500 text-white'
              }`}
            >
              <Ban className="w-3 h-3" />
              <span>{blocked ? 'Blocked in Perimeter' : 'Block IP Now'}</span>
            </button>
          </div>
          <p className="text-slate-200 font-medium text-xs leading-relaxed">
            {event.recommended_action}
          </p>
        </div>

        {/* Model Outputs Breakdown (Section 7 requirement) */}
        <div className="space-y-3">
          <h4 className="text-[11px] uppercase font-mono tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            Model Outputs & Inference Breakdown
          </h4>

          <div className="grid grid-cols-1 gap-2.5">
            {/* Random Forest Supervised Probability */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-300 font-medium">Random Forest Classifier (Supervised)</span>
                <span className="font-mono tabular-nums text-sky-400 font-semibold">
                  {(event.attack_prob * 100).toFixed(1)}% Attack Prob
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-sky-500 h-full rounded-full transition-all duration-300"
                  style={{ width: `${Math.min(100, event.attack_prob * 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Predicted category: <span className="text-slate-300 font-semibold">{event.attack_category}</span> (Severity weight: {event.severity})
              </p>
            </div>

            {/* Isolation Forest Anomaly Score */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-300 font-medium">Isolation Forest (Unsupervised Anomaly)</span>
                <span className="font-mono tabular-nums text-purple-400 font-semibold">
                  {event.anomaly_score.toFixed(2)} / 1.00 Outlier Score
                </span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-purple-500 h-full rounded-full transition-all duration-300"
                  style={{ width: `${Math.min(100, event.anomaly_score * 100)}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Detects out-of-distribution traffic signatures unseen during supervised training
              </p>
            </div>

            {/* Rule-Based SIEM Baseline */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="text-slate-300 font-medium block">Rule-Based SIEM Baseline</span>
                <span className="text-[11px] text-slate-500">Threshold: count &gt; 100 OR src_bytes &gt; 10k OR serror &gt; 0.5</span>
              </div>
              <span
                className={`font-mono text-xs px-2 py-0.5 rounded border ${
                  event.baseline_flag === 1
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                {event.baseline_flag === 1 ? 'FLAGGED' : 'CLEAR'}
              </span>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Mapping */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400 font-semibold">
              Mapped MITRE ATT&CK Technique
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
              {event.mitre_technique.id}
            </span>
          </div>
          <p className="text-sm font-semibold text-slate-100">{event.mitre_technique.name}</p>
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <span>Tactic:</span>
            <span className="text-slate-200 font-medium">{event.mitre_technique.tactic}</span>
          </div>
        </div>

        {/* Network & Asset Context */}
        <div className="space-y-2">
          <h4 className="text-[11px] uppercase font-mono tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-slate-400" />
            Network Topology & Asset Telemetry
          </h4>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
            <div>
              <span className="text-slate-500 block text-[10px]">Source IP (Origin)</span>
              <span className="text-slate-200">{event.src_ip}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Destination IP</span>
              <span className="text-slate-200">{event.dst_ip}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Target Asset</span>
              <span className="text-slate-200 truncate block">{event.destination_asset}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Asset Criticality</span>
              <span className="text-slate-200">{event.asset_criticality} (0.1 - 1.0)</span>
            </div>
          </div>
        </div>

        {/* Raw 41 NSL-KDD Features Grid */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="text-[11px] uppercase font-mono tracking-wider text-slate-400 font-semibold">
              Raw NSL-KDD Features (41 Features)
            </h4>
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          <div className="max-h-60 overflow-y-auto bg-slate-950 rounded-lg border border-slate-800 p-2.5 font-mono text-[11px]">
            <div className="grid grid-cols-2 gap-x-4 gap-y-1">
              {Object.entries(event.raw_features).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between py-0.5 border-b border-slate-900">
                  <span className="text-slate-500 truncate mr-2">{key}:</span>
                  <span className="text-slate-300 font-medium tabular-nums">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
