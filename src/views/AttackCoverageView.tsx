import React, { useState, useMemo } from 'react';
import { Grid, Shield, Search, ExternalLink, Layers, CheckCircle2 } from 'lucide-react';
import { MITRE_TECHNIQUES, MITRE_TACTICS_LIST } from '../data/mitreTechniques';
import { SAMPLE_THREAT_REPORTS } from '../data/sampleReports';
import { ScoredEvent } from '../types/threat';

interface AttackCoverageViewProps {
  events: ScoredEvent[];
  onSelectEvent?: (event: ScoredEvent) => void;
}

export const AttackCoverageView: React.FC<AttackCoverageViewProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTacticFilter, setSelectedTacticFilter] = useState<string>('All');

  // Compute technique detection frequencies across live events
  const techniqueFrequencies = useMemo(() => {
    const counts: Record<string, number> = {};
    MITRE_TECHNIQUES.forEach((t) => {
      counts[t.id] = 0;
    });

    events.forEach((e) => {
      if (counts[e.mitre_technique.id] !== undefined) {
        counts[e.mitre_technique.id] += 1;
      }
    });

    return counts;
  }, [events]);

  // Map which sample threat reports mention each technique
  const techniqueReportsMap = useMemo(() => {
    const map: Record<string, string[]> = {};
    MITRE_TECHNIQUES.forEach((t) => {
      map[t.id] = [];
    });

    SAMPLE_THREAT_REPORTS.forEach((report) => {
      const lower = report.text.toLowerCase();
      MITRE_TECHNIQUES.forEach((t) => {
        const matchesName = lower.includes(t.name.toLowerCase());
        const matchesKeywords = t.keywords.some((k) => lower.includes(k));
        if (matchesName || matchesKeywords) {
          map[t.id].push(report.title);
        }
      });
    });

    return map;
  }, []);

  // Most frequent techniques sorted
  const sortedTechniques = useMemo(() => {
    return [...MITRE_TECHNIQUES].sort((a, b) => {
      const countA = techniqueFrequencies[a.id] || 0;
      const countB = techniqueFrequencies[b.id] || 0;
      return countB - countA;
    });
  }, [techniqueFrequencies]);

  const maxTechniqueCount = sortedTechniques[0] ? (techniqueFrequencies[sortedTechniques[0].id] || 1) : 1;

  // Filtered technique list for table
  const filteredTechniques = useMemo(() => {
    return sortedTechniques.filter((t) => {
      const matchesSearch =
        t.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        t.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesTactic = selectedTacticFilter === 'All' || t.tactic.includes(selectedTacticFilter);
      return matchesSearch && matchesTactic;
    });
  }, [sortedTechniques, searchTerm, selectedTacticFilter]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Context */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <Grid className="w-5 h-5 text-sky-400" />
          MITRE ATT&CK Enterprise Coverage
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Detection matrix correlating 15 core enterprise techniques across tactical phases and threat intelligence reports
        </p>
      </div>

      {/* Heatmap Matrix: Technique (rows) by Tactic (columns) - Section 7 requirement */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Tactical Matrix Heatmap (Techniques &times; Tactics)
            </h3>
            <p className="text-[11px] text-slate-400">
              Cell density indicates occurrence frequency across live telemetry events
            </p>
          </div>

          <div className="flex items-center gap-2 text-[11px] font-mono">
            <span className="text-slate-500">Density:</span>
            <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-500 border border-slate-800">0</span>
            <span className="px-2 py-0.5 rounded bg-sky-950/60 text-sky-400 border border-sky-900/50">1 - 5</span>
            <span className="px-2 py-0.5 rounded bg-sky-800/80 text-sky-200 border border-sky-600/50">6 - 15</span>
            <span className="px-2 py-0.5 rounded bg-sky-500 text-slate-950 font-bold">15+</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-[10px] font-mono text-slate-400 uppercase">
                <th className="py-2.5 px-3 whitespace-nowrap">Technique</th>
                {MITRE_TACTICS_LIST.map((tactic) => (
                  <th key={tactic} className="py-2.5 px-2 text-center whitespace-nowrap">
                    {tactic}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {MITRE_TECHNIQUES.map((tech) => {
                const count = techniqueFrequencies[tech.id] || 0;
                return (
                  <tr key={tech.id} className="hover:bg-slate-800/30">
                    <td className="py-2 px-3 whitespace-nowrap font-medium text-slate-300">
                      <span className="text-sky-400 font-semibold">{tech.id}</span> {tech.name}
                    </td>

                    {MITRE_TACTICS_LIST.map((tactic) => {
                      const matchesTactic = tech.tactic.includes(tactic);

                      let bgClass = 'bg-slate-950 text-slate-700';
                      if (matchesTactic) {
                        if (count === 0) bgClass = 'bg-slate-900/60 text-slate-500 border border-slate-800';
                        else if (count <= 5) bgClass = 'bg-sky-950/80 text-sky-300 border border-sky-900/60 font-semibold';
                        else if (count <= 15) bgClass = 'bg-sky-700/80 text-white font-bold';
                        else bgClass = 'bg-sky-500 text-slate-950 font-extrabold shadow-sm shadow-sky-500/20';
                      }

                      return (
                        <td key={tactic} className="py-1 px-1.5 text-center">
                          {matchesTactic ? (
                            <span className={`inline-block w-8 py-1 rounded text-[10px] tabular-nums ${bgClass}`}>
                              {count}
                            </span>
                          ) : (
                            <span className="text-slate-800">·</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bar Chart of Most Frequent Techniques (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Most Frequent MITRE ATT&CK Techniques
            </h3>
            <p className="text-[11px] text-slate-400">
              Ranked by detected attack events across active network telemetry
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">{sortedTechniques.length} Indexed Techniques</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {sortedTechniques.slice(0, 8).map((tech) => {
            const count = techniqueFrequencies[tech.id] || 0;
            const pct = (count / maxTechniqueCount) * 100;

            return (
              <div key={tech.id} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-sky-400 font-semibold">{tech.id}</span>
                    <span className="font-medium text-slate-200">{tech.name}</span>
                  </div>
                  <span className="font-mono text-sky-400 font-bold tabular-nums">{count} events</span>
                </div>

                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="bg-sky-500 h-full rounded-full transition-all duration-300"
                    style={{ width: `${Math.max(4, pct)}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Tactic: {tech.tactic}</span>
                  <span>{techniqueReportsMap[tech.id]?.length || 0} reports mention</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Table listing each technique with description and mentioned reports (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Technique Catalog & Threat Report Linkages
            </h3>
            <p className="text-[11px] text-slate-400">
              Descriptions and correlating sample CTI reports from data/reports/
            </p>
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search technique or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-1.5 rounded-lg placeholder:text-slate-500 focus:outline-none focus:border-sky-500/50"
            />
            <select
              value={selectedTacticFilter}
              onChange={(e) => setSelectedTacticFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs px-2.5 py-1.5 rounded-lg focus:outline-none"
            >
              <option value="All">All Tactics</option>
              {MITRE_TACTICS_LIST.map((tac) => (
                <option key={tac} value={tac}>{tac}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="space-y-3">
          {filteredTechniques.map((tech) => {
            const reports = techniqueReportsMap[tech.id] || [];
            return (
              <div key={tech.id} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
                      {tech.id}
                    </span>
                    <h4 className="text-sm font-semibold text-slate-100">{tech.name}</h4>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Tactic: <strong className="text-slate-200">{tech.tactic}</strong>
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {tech.description}
                </p>

                {/* Correlated Reports */}
                <div className="pt-2 border-t border-slate-900 flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-[11px] font-mono text-slate-500">Correlated CTI Reports:</span>
                  {reports.length === 0 ? (
                    <span className="text-[11px] text-slate-600 italic">None mentioned directly in current sample corpus</span>
                  ) : (
                    reports.map((rTitle, i) => (
                      <span
                        key={i}
                        className="text-[11px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 font-sans"
                      >
                        {rTitle}
                      </span>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
