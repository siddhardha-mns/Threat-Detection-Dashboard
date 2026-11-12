import React, { useState } from 'react';
import { Sliders, RotateCcw, Save, Check, ShieldCheck, Scale, AlertTriangle } from 'lucide-react';
import { SettingsConfig } from '../types/threat';
import { DEFAULT_SETTINGS } from '../engine/scoringEngine';

interface SettingsViewProps {
  settings: SettingsConfig;
  onUpdateSettings: (newSettings: SettingsConfig) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ settings, onUpdateSettings }) => {
  const [localSettings, setLocalSettings] = useState<SettingsConfig>(settings);
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  // Normalization check: weights sum
  const weightsSum = Math.round(
    (localSettings.weight_attack_prob +
      localSettings.weight_severity +
      localSettings.weight_asset_criticality) *
      100
  ) / 100;

  const handleSave = () => {
    onUpdateSettings(localSettings);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const handleReset = () => {
    setLocalSettings(DEFAULT_SETTINGS);
    onUpdateSettings(DEFAULT_SETTINGS);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <Sliders className="w-5 h-5 text-sky-400" />
          System Configuration & Pipeline Parameters
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Tune continuous risk calculation weights, discrete risk tier boundaries, and semantic MITRE ATT&CK cosine similarity thresholds
        </p>
      </div>

      {/* Settings Form Container */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
        {/* Section 1: Risk Weight Sliders (Section 8 requirement: 0.5, 0.3, 0.2 by default) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Scale className="w-4 h-4 text-sky-400" />
                <span>1. Risk Scoring Engine Formula Weights</span>
              </h3>
              <p className="text-[11px] text-slate-400">
                Formula: risk = 100 &times; (w<sub>attack</sub> &times; P + w<sub>sev</sub> &times; Severity + w<sub>crit</sub> &times; AssetCriticality)
              </p>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-slate-400">Sum:</span>
              <span className={`font-bold ${weightsSum === 1.0 ? 'text-emerald-400' : 'text-amber-400'}`}>
                {weightsSum.toFixed(2)}
              </span>
              {weightsSum !== 1.0 && (
                <span className="text-[10px] text-amber-400 font-sans">(Normalized &le; 1.0 recommended)</span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Weight 1: Attack Prob (0.5) */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">
                  Attack Probability (w<sub>1</sub>)
                </label>
                <span className="font-mono text-xs font-bold text-sky-400">
                  {localSettings.weight_attack_prob.toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0.1}
                max={0.8}
                step={0.05}
                value={localSettings.weight_attack_prob}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, weight_attack_prob: Number(e.target.value) })
                }
                className="w-full accent-sky-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Random Forest probability score</p>
            </div>

            {/* Weight 2: Severity (0.3) */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">
                  Attack Severity (w<sub>2</sub>)
                </label>
                <span className="font-mono text-xs font-bold text-amber-400">
                  {localSettings.weight_severity.toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0.1}
                max={0.6}
                step={0.05}
                value={localSettings.weight_severity}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, weight_severity: Number(e.target.value) })
                }
                className="w-full accent-amber-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Category weight (DoS 0.9, U2R 1.0, etc.)</p>
            </div>

            {/* Weight 3: Asset Criticality (0.2) */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">
                  Asset Criticality (w<sub>3</sub>)
                </label>
                <span className="font-mono text-xs font-bold text-purple-400">
                  {localSettings.weight_asset_criticality.toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0.1}
                max={0.5}
                step={0.05}
                value={localSettings.weight_asset_criticality}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, weight_asset_criticality: Number(e.target.value) })
                }
                className="w-full accent-purple-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Target importance (DB 0.9, Workstation 0.5)</p>
            </div>
          </div>
        </div>

        {/* Section 2: Bucket Thresholds (Low, Med, High, Crit) */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-semibold text-slate-200">
              2. Risk Tier Boundaries (0 to 100 Scale)
            </h3>
            <p className="text-[11px] text-slate-400">
              Control the threshold transitions between Low, Medium, High, and Critical alert levels
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">Low &rarr; Medium Cutoff</label>
                <span className="font-mono text-xs font-bold text-emerald-400">
                  {localSettings.threshold_low_to_med}
                </span>
              </div>
              <input
                type="range"
                min={15}
                max={40}
                value={localSettings.threshold_low_to_med}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, threshold_low_to_med: Number(e.target.value) })
                }
                className="w-full accent-emerald-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Default: 25</p>
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">Medium &rarr; High Cutoff</label>
                <span className="font-mono text-xs font-bold text-amber-400">
                  {localSettings.threshold_med_to_high}
                </span>
              </div>
              <input
                type="range"
                min={40}
                max={65}
                value={localSettings.threshold_med_to_high}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, threshold_med_to_high: Number(e.target.value) })
                }
                className="w-full accent-amber-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Default: 50</p>
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-300">High &rarr; Critical Cutoff</label>
                <span className="font-mono text-xs font-bold text-rose-400">
                  {localSettings.threshold_high_to_crit}
                </span>
              </div>
              <input
                type="range"
                min={65}
                max={90}
                value={localSettings.threshold_high_to_crit}
                onChange={(e) =>
                  setLocalSettings({ ...localSettings, threshold_high_to_crit: Number(e.target.value) })
                }
                className="w-full accent-rose-500 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 font-mono">Default: 75</p>
            </div>
          </div>
        </div>

        {/* Section 3: MITRE Similarity Cutoff (Section 8 requirement) */}
        <div className="space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-semibold text-slate-200">
              3. MITRE ATT&CK Semantic Similarity Threshold
            </h3>
            <p className="text-[11px] text-slate-400">
              Minimum cosine similarity required to map extracted threat report context to a technique candidate
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 max-w-md">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-slate-300">Minimum Cosine Similarity</label>
              <span className="font-mono text-xs font-bold text-sky-400">
                {localSettings.mitre_similarity_threshold.toFixed(2)}
              </span>
            </div>
            <input
              type="range"
              min={0.15}
              max={0.6}
              step={0.05}
              value={localSettings.mitre_similarity_threshold}
              onChange={(e) =>
                setLocalSettings({ ...localSettings, mitre_similarity_threshold: Number(e.target.value) })
              }
              className="w-full accent-sky-500 cursor-pointer"
            />
            <p className="text-[10px] text-slate-500 font-mono">
              Default: 0.30 (Lower yields broader technique matches, higher requires exact terminology)
            </p>
          </div>
        </div>

        {/* Action Buttons: Save & Reset (Section 8 requirement) */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset to Defaults</span>
          </button>

          <div className="flex items-center gap-3">
            {savedSuccess && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                <Check className="w-4 h-4" />
                <span>Configuration Saved!</span>
              </span>
            )}
            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 px-5 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg shadow-sm shadow-sky-600/30 transition-colors cursor-pointer"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save Changes</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
