import React from 'react';
import {
  LayoutDashboard,
  BellRing,
  Globe2,
  Grid,
  FileSearch,
  Gauge,
  PlaySquare,
  Sliders,
  Filter,
  RotateCcw,
  Radio,
} from 'lucide-react';
import { AttackCategory, RiskLevel } from '../types/threat';

export type PageView =
  | 'overview'
  | 'alerts'
  | 'threat-map'
  | 'attack-coverage'
  | 'threat-analyzer'
  | 'model-performance'
  | 'simulate'
  | 'settings';

interface SidebarProps {
  activePage: PageView;
  onPageChange: (page: PageView) => void;
  selectedSeverities: AttackCategory[];
  onToggleSeverity: (cat: AttackCategory) => void;
  selectedRiskLevel: RiskLevel | 'All';
  onSelectRiskLevel: (level: RiskLevel | 'All') => void;
  selectedBatch: string;
  onSelectBatch: (batch: string) => void;
  onResetFilters: () => void;
  isStreaming: boolean;
  onToggleStreaming: () => void;
}

const NAV_ITEMS: { id: PageView; label: string; icon: React.FC<{ className?: string }> }[] = [
  { id: 'overview', label: '1. Overview', icon: LayoutDashboard },
  { id: 'alerts', label: '2. Live Alerts', icon: BellRing },
  { id: 'threat-map', label: '3. Threat Map', icon: Globe2 },
  { id: 'attack-coverage', label: '4. ATT&CK Coverage', icon: Grid },
  { id: 'threat-analyzer', label: '5. Threat Analyzer', icon: FileSearch },
  { id: 'model-performance', label: '6. Model Performance', icon: Gauge },
  { id: 'simulate', label: '7. Simulate Traffic', icon: PlaySquare },
  { id: 'settings', label: '8. Settings', icon: Sliders },
];

const SEVERITIES: AttackCategory[] = ['DoS', 'Probe', 'R2L', 'U2R', 'Normal'];
const RISK_LEVELS: (RiskLevel | 'All')[] = ['All', 'Critical', 'High', 'Medium', 'Low'];

export const Sidebar: React.FC<SidebarProps> = ({
  activePage,
  onPageChange,
  selectedSeverities,
  onToggleSeverity,
  selectedRiskLevel,
  onSelectRiskLevel,
  selectedBatch,
  onSelectBatch,
  onResetFilters,
  isStreaming,
  onToggleStreaming,
}) => {
  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950 flex flex-col shrink-0 overflow-y-auto">
      {/* Navigation section */}
      <div className="p-3 border-b border-slate-800/80">
        <p className="px-3 py-1.5 text-[10px] uppercase font-mono tracking-wider text-slate-500 font-semibold">
          Console Navigation
        </p>
        <nav className="space-y-0.5 mt-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onPageChange(item.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors text-left ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-300 font-semibold border border-sky-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Real-time streaming simulation switch */}
      <div className="p-4 border-b border-slate-800/80">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className={`w-3.5 h-3.5 ${isStreaming ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="text-xs font-medium text-slate-300">Live Traffic Stream</span>
          </div>
          <button
            onClick={onToggleStreaming}
            className={`text-[11px] font-mono px-2 py-0.5 rounded transition-colors ${
              isStreaming
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isStreaming ? 'STREAMING' : 'OFF'}
          </button>
        </div>
      </div>

      {/* Global filters sidebar elements as specified in Section 7 */}
      <div className="p-4 space-y-4 flex-1">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs font-semibold">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Global Pipeline Filters</span>
          </div>
          <button
            onClick={onResetFilters}
            className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 transition-colors"
            title="Reset all filters"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset</span>
          </button>
        </div>

        {/* Date / Batch Selector */}
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
            Telemetry Batch
          </label>
          <select
            value={selectedBatch}
            onChange={(e) => onSelectBatch(e.target.value)}
            className="w-full text-xs bg-slate-900 border border-slate-800 text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-sky-500/50"
          >
            <option value="all">All Indexed Batches</option>
            <option value="last_1h">Past 1 Hour</option>
            <option value="last_6h">Past 6 Hours</option>
            <option value="last_24h">Past 24 Hours (Full NSL-KDD)</option>
          </select>
        </div>

        {/* Attack Category Multi-Select Filter */}
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
            Severity / Attack Category
          </label>
          <div className="grid grid-cols-2 gap-1.5">
            {SEVERITIES.map((cat) => {
              const isSelected = selectedSeverities.includes(cat);
              return (
                <button
                  key={cat}
                  onClick={() => onToggleSeverity(cat)}
                  className={`text-[11px] font-mono py-1 px-2 rounded border text-left transition-colors ${
                    isSelected
                      ? 'bg-slate-800 text-sky-300 border-sky-500/40'
                      : 'bg-slate-900/60 text-slate-500 border-slate-800/80 hover:text-slate-300'
                  }`}
                >
                  {isSelected ? '✓ ' : '  '}{cat}
                </button>
              );
            })}
          </div>
        </div>

        {/* Risk Level Filter */}
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1.5">
            Risk Level Bucket
          </label>
          <div className="space-y-1">
            {RISK_LEVELS.map((level) => {
              const isSelected = selectedRiskLevel === level;
              return (
                <button
                  key={level}
                  onClick={() => onSelectRiskLevel(level)}
                  className={`w-full text-left text-xs px-2.5 py-1 rounded transition-colors flex items-center justify-between ${
                    isSelected
                      ? 'bg-sky-500/15 text-sky-300 border border-sky-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <span>{level}</span>
                  {level === 'Critical' && <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />}
                  {level === 'High' && <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />}
                  {level === 'Medium' && <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />}
                  {level === 'Low' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </aside>
  );
};
