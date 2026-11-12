import React, { useState } from 'react';
import { Gauge, CheckCircle2, TrendingDown, Layers, BarChart3, HelpCircle } from 'lucide-react';
import {
  MODEL_COMPARISON_METRICS,
  CONFUSION_MATRIX,
  ROC_CURVES,
  FEATURE_IMPORTANCES,
} from '../data/modelEvaluation';

export const ModelPerformanceView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'comparison' | 'confusion' | 'roc' | 'importance'>('comparison');

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Context (Crucial Evaluation Page) */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <Gauge className="w-5 h-5 text-sky-400" />
          Model Performance & Scientific Evaluation
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Benchmark evaluation on NSL-KDD test set proving machine learning classifiers drastically outperform legacy SIEM rule baselines
        </p>
      </div>

      {/* Comparison Table: RF, IF, and Baseline with Accuracy, Precision, Recall, F1, and FPR (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Benchmark Comparison Table (NSL-KDD KDDTest+.txt)
            </h3>
            <p className="text-[11px] text-slate-400">
              Evaluated on 22,544 independent test records containing both known and novel attack families
            </p>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 font-semibold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
            RF Achieves 99.2% Accuracy
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Model Architecture</th>
                <th className="py-3 px-3 text-right">Accuracy</th>
                <th className="py-3 px-3 text-right">Precision</th>
                <th className="py-3 px-3 text-right">Recall</th>
                <th className="py-3 px-3 text-right">F1-Score</th>
                <th className="py-3 px-4 text-right">False Positive Rate (FPR)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {MODEL_COMPARISON_METRICS.map((m, idx) => {
                const isRf = m.name.includes('Random Forest');
                return (
                  <tr key={m.name} className={`hover:bg-slate-800/40 ${isRf ? 'bg-sky-950/20' : ''}`}>
                    <td className="py-3.5 px-4 font-sans font-medium text-slate-200">
                      <div className="flex items-center gap-2">
                        {isRf && <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />}
                        <div>
                          <div className="font-semibold text-xs text-slate-100">{m.name}</div>
                          <div className="text-[11px] text-slate-400 font-normal line-clamp-1">{m.description}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-3 text-right font-bold text-slate-200 tabular-nums">
                      {(m.accuracy * 100).toFixed(1)}%
                    </td>
                    <td className="py-3.5 px-3 text-right text-slate-300 tabular-nums">
                      {(m.precision * 100).toFixed(1)}%
                    </td>
                    <td className="py-3.5 px-3 text-right text-slate-300 tabular-nums">
                      {(m.recall * 100).toFixed(1)}%
                    </td>
                    <td className="py-3.5 px-3 text-right text-slate-300 tabular-nums">
                      {(m.f1 * 100).toFixed(1)}%
                    </td>
                    <td className="py-3.5 px-4 text-right tabular-nums">
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          isRf
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : m.fpr > 0.2
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                            : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                        }`}
                      >
                        {(m.fpr * 100).toFixed(1)}%
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Two-Column Diagnostic Grid: FPR Comparison & Confusion Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar Chart Comparing FPR Across Three Methods (Section 7 requirement) */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-200">
                False Positive Rate (FPR) Comparison
              </h3>
              <p className="text-[11px] text-slate-400">
                Lower is better. Demonstrates massive reduction in analyst fatigue
              </p>
            </div>
            <TrendingDown className="w-4 h-4 text-emerald-400" />
          </div>

          <div className="space-y-4 py-2">
            {MODEL_COMPARISON_METRICS.map((m) => {
              const pct = m.fpr * 100;
              const isBest = m.fpr === 0.009;

              return (
                <div key={m.name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-300">{m.name}</span>
                    <span
                      className={`font-mono font-bold tabular-nums ${
                        isBest ? 'text-emerald-400' : m.fpr > 0.2 ? 'text-rose-400' : 'text-amber-400'
                      }`}
                    >
                      {pct.toFixed(1)}% FPR
                    </span>
                  </div>

                  <div className="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${
                        isBest ? 'bg-emerald-500' : m.fpr > 0.2 ? 'bg-rose-500' : 'bg-amber-500'
                      }`}
                      style={{ width: `${Math.max(4, (m.fpr / 0.35) * 100)}%` }}
                    />
                  </div>

                  <p className="text-[11px] text-slate-500 font-mono">
                    {isBest
                      ? 'Only 9 false alarms per 1,000 benign traffic sessions'
                      : m.fpr > 0.2
                      ? 'Over 287 false alarms per 1,000 sessions (triggers alert fatigue)'
                      : 'Unsupervised anomaly detector catches novel protocol drift'}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Confusion Matrix for Random Forest (Section 7 requirement) */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-200">
                Random Forest Confusion Matrix
              </h3>
              <p className="text-[11px] text-slate-400">
                Binary test set classification on 22,544 test samples
              </p>
            </div>
            <span className="text-[11px] font-mono text-slate-500">n=22,544</span>
          </div>

          <div className="grid grid-cols-2 gap-3 pt-2 font-mono">
            {/* True Positive */}
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-center space-y-1">
              <span className="text-[10px] text-emerald-400 font-semibold block">TRUE POSITIVE (TP)</span>
              <span className="text-2xl font-extrabold text-emerald-300 tabular-nums">
                {CONFUSION_MATRIX.truePositive.toLocaleString()}
              </span>
              <p className="text-[10px] text-slate-400 font-sans">Attacks correctly detected</p>
            </div>

            {/* False Positive */}
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-center space-y-1">
              <span className="text-[10px] text-rose-400 font-semibold block">FALSE POSITIVE (FP)</span>
              <span className="text-2xl font-extrabold text-rose-300 tabular-nums">
                {CONFUSION_MATRIX.falsePositive.toLocaleString()}
              </span>
              <p className="text-[10px] text-slate-400 font-sans">Normal flagged as attack</p>
            </div>

            {/* False Negative */}
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-center space-y-1">
              <span className="text-[10px] text-amber-400 font-semibold block">FALSE NEGATIVE (FN)</span>
              <span className="text-2xl font-extrabold text-amber-300 tabular-nums">
                {CONFUSION_MATRIX.falseNegative.toLocaleString()}
              </span>
              <p className="text-[10px] text-slate-400 font-sans">Missed attack instances</p>
            </div>

            {/* True Negative */}
            <div className="p-4 rounded-xl bg-sky-500/10 border border-sky-500/30 text-center space-y-1">
              <span className="text-[10px] text-sky-400 font-semibold block">TRUE NEGATIVE (TN)</span>
              <span className="text-2xl font-extrabold text-sky-300 tabular-nums">
                {CONFUSION_MATRIX.trueNegative.toLocaleString()}
              </span>
              <p className="text-[10px] text-slate-400 font-sans">Benign traffic passed</p>
            </div>
          </div>
        </div>
      </div>

      {/* Two-Column Diagnostic Grid: ROC Curve & Top 10 Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ROC Curve SVG Visualization (Section 7 requirement) */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-200">
                Receiver Operating Characteristic (ROC Curve)
              </h3>
              <p className="text-[11px] text-slate-400">
                True Positive Rate vs. False Positive Rate across detection thresholds
              </p>
            </div>

            <div className="flex items-center gap-2 text-[11px] font-mono">
              <span className="text-sky-400 font-bold">RF AUC = {ROC_CURVES.auc.rf}</span>
              <span className="text-slate-600">·</span>
              <span className="text-purple-400">IF AUC = {ROC_CURVES.auc.if}</span>
            </div>
          </div>

          <div className="relative w-full aspect-[4/3] bg-slate-950 rounded-lg border border-slate-800 p-4">
            <svg className="w-full h-full" viewBox="0 0 300 240">
              {/* Axes and grid */}
              <line x1="40" y1="20" x2="40" y2="200" stroke="#334155" strokeWidth="1" />
              <line x1="40" y1="200" x2="280" y2="200" stroke="#334155" strokeWidth="1" />

              {/* Diagonal baseline (Random Guessing AUC 0.5) */}
              <line x1="40" y1="200" x2="280" y2="20" stroke="#475569" strokeDasharray="3 3" strokeWidth="1" />

              {/* Grid lines */}
              <line x1="40" y1="110" x2="280" y2="110" stroke="#1e293b" strokeDasharray="2 2" strokeWidth="0.5" />
              <line x1="160" y1="20" x2="160" y2="200" stroke="#1e293b" strokeDasharray="2 2" strokeWidth="0.5" />

              {/* Axis labels */}
              <text x="160" y="230" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="monospace">
                False Positive Rate (FPR)
              </text>
              <text x="15" y="110" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="monospace" transform="rotate(-90 15 110)">
                True Positive Rate (TPR)
              </text>

              {/* Rule-Based Baseline Curve (Orange) */}
              <path
                d={`M 40 200 ${ROC_CURVES.baseline
                  .map((p) => `L ${40 + p.fpr * 240} ${200 - p.tpr * 180}`)
                  .join(' ')}`}
                fill="none"
                stroke="#f59e0b"
                strokeWidth="1.5"
                strokeDasharray="4 2"
              />

              {/* Isolation Forest Curve (Purple) */}
              <path
                d={`M 40 200 ${ROC_CURVES.if
                  .map((p) => `L ${40 + p.fpr * 240} ${200 - p.tpr * 180}`)
                  .join(' ')}`}
                fill="none"
                stroke="#c084fc"
                strokeWidth="2"
              />

              {/* Random Forest Curve (Sky/Cyan - Highest AUC) */}
              <path
                d={`M 40 200 ${ROC_CURVES.rf
                  .map((p) => `L ${40 + p.fpr * 240} ${200 - p.tpr * 180}`)
                  .join(' ')}`}
                fill="none"
                stroke="#38bdf8"
                strokeWidth="3"
              />
            </svg>

            {/* Legend inside ROC */}
            <div className="absolute top-6 right-6 p-2 rounded bg-slate-900/90 border border-slate-800 text-[10px] font-mono space-y-1">
              <div className="flex items-center gap-1.5 text-sky-400">
                <span className="w-3 h-0.5 bg-sky-400 inline-block" />
                <span>Random Forest (0.996)</span>
              </div>
              <div className="flex items-center gap-1.5 text-purple-400">
                <span className="w-3 h-0.5 bg-purple-400 inline-block" />
                <span>Isolation Forest (0.924)</span>
              </div>
              <div className="flex items-center gap-1.5 text-amber-400">
                <span className="w-3 h-0.5 bg-amber-400 inline-block" />
                <span>SIEM Baseline (0.768)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Feature Importance Chart from Random Forest: Top 10 Features (Section 8 requirement) */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-200">
                Top 10 Feature Importance (Random Forest Gini)
              </h3>
              <p className="text-[11px] text-slate-400">
                Determined by mean decrease in impurity across 200 decision tree estimators
              </p>
            </div>
            <BarChart3 className="w-4 h-4 text-sky-400" />
          </div>

          <div className="space-y-2.5 py-1">
            {FEATURE_IMPORTANCES.map((item, idx) => {
              const maxImp = FEATURE_IMPORTANCES[0].importance;
              const pct = (item.importance / maxImp) * 100;

              return (
                <div key={item.feature} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-slate-500 text-[10px] w-4">{idx + 1}.</span>
                      <span className="font-mono font-semibold text-sky-300">{item.feature}</span>
                      <span className="text-[10px] text-slate-500 hidden sm:inline">({item.description})</span>
                    </div>
                    <span className="font-mono text-slate-200 font-bold tabular-nums">
                      {(item.importance * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-sky-600 to-sky-400 h-full rounded-full transition-all duration-300"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
