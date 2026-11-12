import React from 'react';
import { ShieldAlert, Terminal, RefreshCw, Sparkles, Code2 } from 'lucide-react';

interface HeaderProps {
  eventCount: number;
  criticalCount: number;
  onQuickSimulate: () => void;
  onOpenPythonModal: () => void;
  isSimulating: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  eventCount,
  criticalCount,
  onQuickSimulate,
  onOpenPythonModal,
  isSimulating,
}) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md px-6 flex items-center justify-between gap-6 shrink-0 sticky top-0 z-30">
      {/* Zone 1: Brand & Simulated Data Badge */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shadow-sm shadow-sky-500/10">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 tracking-tight text-base whitespace-nowrap">
                ThreatIntel SOC
              </span>
              <span className="text-[11px] font-mono tracking-wider px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 whitespace-nowrap">
                Simulated data
              </span>
            </div>
            <p className="text-[11px] text-slate-400 whitespace-nowrap">
              NSL-KDD Dual ML Classifier & MITRE ATT&CK Engine
            </p>
          </div>
        </div>
      </div>

      {/* Zone 2: Telemetry status counters */}
      <div className="hidden lg:flex items-center gap-5 text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <span className="text-slate-500">Live Buffer:</span>
          <span className="font-mono text-slate-200 tabular-nums font-semibold">{eventCount} events</span>
        </div>
        <span className="text-slate-700" aria-hidden="true">·</span>
        <div className="flex items-center gap-2">
          <span className="text-slate-500">Critical Incidents:</span>
          <span className={`font-mono tabular-nums font-semibold ${criticalCount > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
            {criticalCount} active
          </span>
        </div>
        <span className="text-slate-700" aria-hidden="true">·</span>
        <div className="flex items-center gap-1.5 text-slate-300">
          <Sparkles className="w-3.5 h-3.5 text-sky-400" />
          <span>Gemini 3.8 Flash CTI Ready</span>
        </div>
      </div>

      {/* Zone 3: Actions */}
      <div className="flex items-center gap-2.5 shrink-0">
        <button
          onClick={onOpenPythonModal}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-700/80 rounded-lg hover:bg-slate-800 hover:text-white transition-colors whitespace-nowrap"
          title="View and download standalone Python modules"
        >
          <Code2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>Python Scripts</span>
        </button>

        <button
          onClick={onQuickSimulate}
          disabled={isSimulating}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 disabled:opacity-50 rounded-lg shadow-sm shadow-sky-600/30 transition-colors whitespace-nowrap cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
          <span>{isSimulating ? 'Scoring Batch...' : 'Simulate +25 Events'}</span>
        </button>
      </div>
    </header>
  );
};
