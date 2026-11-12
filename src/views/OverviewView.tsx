import React from 'react';
import {
  ShieldAlert,
  AlertOctagon,
  TrendingDown,
  Activity,
  Layers,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { ScoredEvent } from '../types/threat';

interface OverviewViewProps {
  events: ScoredEvent[];
  onSelectEvent: (event: ScoredEvent) => void;
  onNavigateToAlerts: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  events,
  onSelectEvent,
  onNavigateToAlerts,
}) => {
  const totalEvents = events.length;
  const attacksDetected = events.filter((e) => e.attack_category !== 'Normal').length;
  const criticalAlerts = events.filter((e) => e.risk_level === 'Critical').length;
  const avgRiskScore = totalEvents > 0
    ? Math.round((events.reduce((sum, e) => sum + e.risk_score, 0) / totalEvents) * 10) / 10
    : 0;

  // Breakdown by risk level
  const riskCounts = {
    Critical: events.filter((e) => e.risk_level === 'Critical').length,
    High: events.filter((e) => e.risk_level === 'High').length,
    Medium: events.filter((e) => e.risk_level === 'Medium').length,
    Low: events.filter((e) => e.risk_level === 'Low').length,
  };

  // Breakdown by attack category
  const categoryCounts = {
    DoS: events.filter((e) => e.attack_category === 'DoS').length,
    Probe: events.filter((e) => e.attack_category === 'Probe').length,
    R2L: events.filter((e) => e.attack_category === 'R2L').length,
    U2R: events.filter((e) => e.attack_category === 'U2R').length,
    Normal: events.filter((e) => e.attack_category === 'Normal').length,
  };

  const top5Events = [...events].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

  // Donut chart math
  const totalForDonut = totalEvents || 1;
  const pCritical = (riskCounts.Critical / totalForDonut) * 100;
  const pHigh = (riskCounts.High / totalForDonut) * 100;
  const pMedium = (riskCounts.Medium / totalForDonut) * 100;
  const pLow = (riskCounts.Low / totalForDonut) * 100;

  // Timeline slices (recent 12 buckets)
  const timelineBuckets = Array.from({ length: 12 }, (_, i) => {
    const chunk = events.slice(i * 12, (i + 1) * 12);
    const attacks = chunk.filter((e) => e.attack_category !== 'Normal').length;
    return { index: i + 1, total: chunk.length, attacks };
  }).reverse();

  const maxAttacksInBucket = Math.max(...timelineBuckets.map((b) => b.attacks), 1);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Context */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight">
          Executive Security Posture Overview
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          High-level operational summary from continuous NSL-KDD machine learning scoring and telemetry correlation
        </p>
      </div>

      {/* KPI Cards Strip (Section 7 requirement: total events, attacks detected, critical alerts, false-positive rate, average risk score) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Events */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Total Events Ingested</span>
            <Layers className="w-4 h-4 text-slate-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
              {totalEvents}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">records</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Across 15 global geolocations
          </div>
        </div>

        {/* Attacks Detected */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Attacks Detected</span>
            <ShieldAlert className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-sky-400 tabular-nums">
              {attacksDetected}
            </span>
            <span className="text-[11px] text-slate-400 font-mono">
              ({totalEvents > 0 ? Math.round((attacksDetected / totalEvents) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Random Forest supervised model
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Critical Alerts</span>
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-rose-400 tabular-nums">
              {criticalAlerts}
            </span>
            <span className="text-[11px] text-slate-400 font-mono">score &ge; 75</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Requiring immediate containment
          </div>
        </div>

        {/* False-Positive Rate (ML vs Baseline) */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">False Positive Rate</span>
            <TrendingDown className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
              0.9%
            </span>
            <span className="text-[11px] text-slate-500 line-through">28.7%</span>
          </div>
          <div className="mt-2 text-[11px] text-emerald-400/90 flex items-center gap-1 font-mono">
            <span>-96.8% vs SIEM baseline</span>
          </div>
        </div>

        {/* Average Risk Score */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-medium">Average Risk Score</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
              {avgRiskScore}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Weighted risk engine aggregate
          </div>
        </div>
      </div>

      {/* Visual Analytics Grid: Donut + Bar Chart + Activity Line */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Donut Chart: Events by Risk Level */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-slate-200">Events by Risk Level</h3>
            <span className="text-[11px] font-mono text-slate-500">Continuous Buckets</span>
          </div>

          <div className="flex-1 flex flex-col items-center justify-center py-2">
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                {/* Background Track */}
                <circle cx="50" cy="50" r="38" fill="none" stroke="#1e293b" strokeWidth="12" />
                {/* Segments: Critical (Rose), High (Orange), Medium (Amber), Low (Emerald) */}
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#f43f5e"
                  strokeWidth="12"
                  strokeDasharray={`${pCritical * 2.38} 238`}
                  strokeDashoffset="0"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#f97316"
                  strokeWidth="12"
                  strokeDasharray={`${pHigh * 2.38} 238`}
                  strokeDashoffset={`-${pCritical * 2.38}`}
                />
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#f59e0b"
                  strokeWidth="12"
                  strokeDasharray={`${pMedium * 2.38} 238`}
                  strokeDashoffset={`-${(pCritical + pHigh) * 2.38}`}
                />
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="12"
                  strokeDasharray={`${pLow * 2.38} 238`}
                  strokeDashoffset={`-${(pCritical + pHigh + pMedium) * 2.38}`}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold font-mono text-slate-100">{totalEvents}</span>
                <span className="text-[10px] text-slate-400 font-mono">SCORED</span>
              </div>
            </div>

            <div className="w-full grid grid-cols-2 gap-2 mt-4 text-xs font-mono">
              <div className="flex items-center justify-between p-1.5 rounded bg-slate-950 border border-slate-800/80">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span className="text-slate-300">Critical</span>
                </div>
                <span className="font-semibold text-rose-400 tabular-nums">{riskCounts.Critical}</span>
              </div>
              <div className="flex items-center justify-between p-1.5 rounded bg-slate-950 border border-slate-800/80">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-orange-500" />
                  <span className="text-slate-300">High</span>
                </div>
                <span className="font-semibold text-orange-400 tabular-nums">{riskCounts.High}</span>
              </div>
              <div className="flex items-center justify-between p-1.5 rounded bg-slate-950 border border-slate-800/80">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                  <span className="text-slate-300">Medium</span>
                </div>
                <span className="font-semibold text-amber-400 tabular-nums">{riskCounts.Medium}</span>
              </div>
              <div className="flex items-center justify-between p-1.5 rounded bg-slate-950 border border-slate-800/80">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span className="text-slate-300">Low</span>
                </div>
                <span className="font-semibold text-emerald-400 tabular-nums">{riskCounts.Low}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bar Chart: Attacks by Category */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-slate-200">Attacks by Category</h3>
            <span className="text-[11px] font-mono text-slate-500">NSL-KDD 4 Groups</span>
          </div>

          <div className="flex-1 flex flex-col justify-around py-2 space-y-3">
            {[
              { cat: 'DoS (Denial of Service)', count: categoryCounts.DoS, color: 'bg-sky-500', text: 'text-sky-400', max: Math.max(...Object.values(categoryCounts), 1) },
              { cat: 'Probe (Surveillance / Recon)', count: categoryCounts.Probe, color: 'bg-amber-500', text: 'text-amber-400', max: Math.max(...Object.values(categoryCounts), 1) },
              { cat: 'R2L (Remote to Local)', count: categoryCounts.R2L, color: 'bg-violet-500', text: 'text-violet-400', max: Math.max(...Object.values(categoryCounts), 1) },
              { cat: 'U2R (User to Root)', count: categoryCounts.U2R, color: 'bg-rose-500', text: 'text-rose-400', max: Math.max(...Object.values(categoryCounts), 1) },
              { cat: 'Normal (Benign Traffic)', count: categoryCounts.Normal, color: 'bg-emerald-500', text: 'text-emerald-400', max: Math.max(...Object.values(categoryCounts), 1) },
            ].map((item) => (
              <div key={item.cat} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium">{item.cat}</span>
                  <span className={`font-mono tabular-nums font-semibold ${item.text}`}>{item.count}</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className={`${item.color} h-full rounded-full transition-all duration-300`}
                    style={{ width: `${Math.max(4, (item.count / item.max) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Line / Histogram Chart: Attacks Over Time */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-slate-200">Attack Velocity Timeline</h3>
            <span className="text-[11px] font-mono text-slate-500">Recent Windows</span>
          </div>

          <div className="flex-1 flex flex-col justify-end">
            <div className="h-44 flex items-end gap-2 pt-6">
              {timelineBuckets.map((bucket, idx) => {
                const heightPct = Math.max(8, (bucket.attacks / maxAttacksInBucket) * 100);
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 group relative">
                    {/* Tooltip */}
                    <div className="absolute -top-7 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-950 text-slate-200 border border-slate-700 text-[10px] font-mono py-0.5 px-1.5 rounded pointer-events-none whitespace-nowrap z-20">
                      {bucket.attacks} attacks / {bucket.total} events
                    </div>

                    <div className="w-full bg-slate-800/80 rounded-t overflow-hidden flex flex-col justify-end h-full">
                      <div
                        className="w-full bg-gradient-to-t from-sky-600 to-sky-400 rounded-t transition-all duration-300"
                        style={{ height: `${heightPct}%` }}
                      />
                    </div>
                    <span className="text-[9px] font-mono text-slate-500">w{idx + 1}</span>
                  </div>
                );
              })}
            </div>
            <p className="text-[11px] text-slate-500 text-center mt-3 font-mono">
              Event frequency index across 24h simulation window
            </p>
          </div>
        </div>
      </div>

      {/* Top 5 Highest-Risk Events Table (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Top 5 Highest-Risk Events (Immediate Triage)
            </h3>
            <p className="text-[11px] text-slate-400">
              Correlated by combined attack probability, severity weight, and asset criticality
            </p>
          </div>

          <button
            onClick={onNavigateToAlerts}
            className="flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 transition-colors cursor-pointer"
          >
            <span>View Full Live Queue</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase">
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination Asset</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">MITRE Technique</th>
                <th className="py-2.5 px-3 text-right">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {top5Events.map((evt) => (
                <tr
                  key={evt.event_id}
                  onClick={() => onSelectEvent(evt)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                >
                  <td className="py-2.5 px-3 font-semibold text-sky-400">{evt.event_id}</td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {evt.src_ip}
                    <span className="text-[10px] text-slate-500 ml-1.5 font-sans">({evt.country})</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs">{evt.destination_asset}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {evt.attack_category}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">
                    <span className="text-sky-300 font-semibold">{evt.mitre_technique.id}</span> {evt.mitre_technique.name}
                  </td>
                  <td className="py-2.5 px-3 text-right font-bold text-rose-400 tabular-nums">
                    {evt.risk_score} <span className="text-[10px] text-rose-500/80">CRITICAL</span>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="text-[11px] text-sky-400 group-hover:underline flex items-center justify-end gap-1 font-sans">
                      Inspect <ExternalLink className="w-3 h-3" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
