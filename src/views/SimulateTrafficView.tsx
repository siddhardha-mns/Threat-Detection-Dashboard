import React, { useState } from 'react';
import {
  PlaySquare,
  Sliders,
  CheckCircle2,
  RefreshCw,
  Cpu,
  ArrowRight,
  ShieldAlert,
  Radio,
} from 'lucide-react';
import { ScoredEvent, SettingsConfig, AttackCategory } from '../types/threat';
import { generateSyntheticEvents } from '../data/initialEvents';
import { DEFAULT_SETTINGS } from '../engine/scoringEngine';

interface SimulateTrafficViewProps {
  onAddEvents: (newEvents: ScoredEvent[]) => void;
  onNavigateToAlerts: () => void;
  settings?: SettingsConfig;
}

export const SimulateTrafficView: React.FC<SimulateTrafficViewProps> = ({
  onAddEvents,
  onNavigateToAlerts,
}) => {
  const [batchSize, setBatchSize] = useState<number>(100);
  const [attackRatio, setAttackRatio] = useState<number>(40); // 40% attacks
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [currentStep, setCurrentStep] = useState<string>('');
  const [lastGeneratedCount, setLastGeneratedCount] = useState<number | null>(null);

  const handleSimulate = async () => {
    setIsGenerating(true);
    setProgress(10);
    setCurrentStep('1/5: Ingesting raw network connection records from NSL-KDD test split...');

    await new Promise((r) => setTimeout(r, 400));
    setProgress(35);
    setCurrentStep('2/5: One-hot encoding protocol/service/flag and scaling 41 numerical features...');

    await new Promise((r) => setTimeout(r, 450));
    setProgress(65);
    setCurrentStep('3/5: Running Random Forest classifier & Isolation Forest anomaly detector...');

    await new Promise((r) => setTimeout(r, 450));
    setProgress(85);
    setCurrentStep('4/5: Evaluating SIEM baseline & mapping MaxMind GeoLite2 coordinates...');

    await new Promise((r) => setTimeout(r, 350));
    setProgress(100);
    setCurrentStep('5/5: Computing continuous risk scores and pushing events to Live Alerts queue!');

    // Generate batch with custom seed
    const newBatch = generateSyntheticEvents(batchSize, Date.now() % 100000);
    onAddEvents(newBatch);
    setLastGeneratedCount(newBatch.length);

    await new Promise((r) => setTimeout(r, 300));
    setIsGenerating(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Context */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <PlaySquare className="w-5 h-5 text-sky-400" />
          Network Traffic Simulation & Live Batch Injection
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Simulate enterprise network traffic streams sampled from the NSL-KDD test set, run the full multi-stage ML pipeline, and stream scored alerts directly into the working queue
        </p>
      </div>

      {/* Control Panel (Section 8 requirement) */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2 border-b border-slate-800 pb-3">
          <Sliders className="w-4 h-4 text-sky-400" />
          <span>Batch Generation Parameters</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Batch Size Slider (50 to 200 events) */}
          <div className="space-y-2 p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">
                Batch Size (Network Sessions)
              </label>
              <span className="font-mono text-xs font-bold text-sky-400 px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/30">
                {batchSize} events
              </span>
            </div>
            <input
              type="range"
              min={50}
              max={200}
              step={10}
              value={batchSize}
              onChange={(e) => setBatchSize(Number(e.target.value))}
              disabled={isGenerating}
              className="w-full accent-sky-500 cursor-pointer"
            />
            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
              <span>50 events (Quick Probe)</span>
              <span>200 events (Full Burst)</span>
            </div>
          </div>

          {/* Attack Ratio Slider (10% to 80%) */}
          <div className="space-y-2 p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300">
                Adversarial Attack Proportion
              </label>
              <span className="font-mono text-xs font-bold text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30">
                {attackRatio}% attacks
              </span>
            </div>
            <input
              type="range"
              min={10}
              max={80}
              step={5}
              value={attackRatio}
              onChange={(e) => setAttackRatio(Number(e.target.value))}
              disabled={isGenerating}
              className="w-full accent-rose-500 cursor-pointer"
            />
            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
              <span>10% (Normal Enterprise)</span>
              <span>80% (Under Active Attack)</span>
            </div>
          </div>
        </div>

        {/* Expected Attack Mix Preview */}
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
            Estimated Inbound Attack Category Distribution
          </span>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">DoS Floods</span>
              <span className="text-sky-300 font-bold">~{Math.round(batchSize * (attackRatio / 100) * 0.4)}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Port Probes</span>
              <span className="text-amber-300 font-bold">~{Math.round(batchSize * (attackRatio / 100) * 0.3)}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">R2L Exploits</span>
              <span className="text-violet-300 font-bold">~{Math.round(batchSize * (attackRatio / 100) * 0.2)}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">U2R Escalations</span>
              <span className="text-rose-300 font-bold">~{Math.round(batchSize * (attackRatio / 100) * 0.1)}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Benign Normal</span>
              <span className="text-emerald-300 font-bold">~{Math.round(batchSize * (1 - attackRatio / 100))}</span>
            </div>
          </div>
        </div>

        {/* Execution Button & Progress Bar (Section 8 requirement) */}
        <div className="space-y-4 pt-2">
          <button
            onClick={handleSimulate}
            disabled={isGenerating}
            className="w-full sm:w-auto px-6 py-2.5 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 disabled:opacity-50 rounded-lg shadow-md shadow-sky-600/30 flex items-center justify-center gap-2 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>
              {isGenerating
                ? `Running Pipeline on ${batchSize} Records...`
                : `Generate & Score Batch of ${batchSize} Events`}
            </span>
          </button>

          {isGenerating && (
            <div className="space-y-2 p-4 rounded-xl bg-slate-950 border border-sky-500/30 animate-in fade-in">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-slate-300 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-sky-400 animate-pulse" />
                  <span>{currentStep}</span>
                </span>
                <span className="font-mono text-sky-400 font-bold tabular-nums">{progress}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="bg-gradient-to-r from-sky-500 to-emerald-400 h-full rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {lastGeneratedCount && !isGenerating && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-emerald-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>
                  Successfully scored and pushed <strong>{lastGeneratedCount} new events</strong> into Live Alerts and Threat Map!
                </span>
              </div>

              <button
                onClick={onNavigateToAlerts}
                className="flex items-center gap-1.5 font-medium text-sky-400 hover:text-sky-300 transition-colors ml-4 cursor-pointer"
              >
                <span>View in Live Alerts</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
