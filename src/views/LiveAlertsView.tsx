import React, { useState, useMemo } from 'react';
import {
  Download,
  Search,
  ArrowUpDown,
  Filter,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
} from 'lucide-react';
import { ScoredEvent, RiskLevel } from '../types/threat';

interface LiveAlertsViewProps {
  events: ScoredEvent[];
  onSelectEvent: (event: ScoredEvent) => void;
  selectedEventId?: string;
}

type SortField = 'timestamp' | 'risk_score' | 'attack_category' | 'event_id';
type SortOrder = 'asc' | 'desc';

export const LiveAlertsView: React.FC<LiveAlertsViewProps> = ({
  events,
  onSelectEvent,
  selectedEventId,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<SortField>('risk_score');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  // Filtered & sorted alerts
  const filteredEvents = useMemo(() => {
    let result = [...events];

    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      result = result.filter(
        (e) =>
          e.event_id.toLowerCase().includes(q) ||
          e.src_ip.includes(q) ||
          e.destination_asset.toLowerCase().includes(q) ||
          e.attack_category.toLowerCase().includes(q) ||
          e.country.toLowerCase().includes(q) ||
          e.mitre_technique.name.toLowerCase().includes(q) ||
          e.mitre_technique.id.toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'risk_score') cmp = a.risk_score - b.risk_score;
      else if (sortField === 'timestamp') cmp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      else if (sortField === 'attack_category') cmp = a.attack_category.localeCompare(b.attack_category);
      else if (sortField === 'event_id') cmp = a.event_id.localeCompare(b.event_id);
      return sortOrder === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [events, searchTerm, sortField, sortOrder]);

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
  const paginatedEvents = filteredEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // CSV Export feature (Section 7 requirement)
  const handleExportCSV = () => {
    const headers = [
      'event_id',
      'timestamp',
      'src_ip',
      'dst_ip',
      'country',
      'destination_asset',
      'attack_category',
      'attack_prob',
      'anomaly_score',
      'baseline_flag',
      'severity',
      'risk_score',
      'risk_level',
      'mitre_technique_id',
      'mitre_technique_name',
      'mitre_tactic',
      'recommended_action',
    ];

    const rows = filteredEvents.map((e) => [
      e.event_id,
      e.timestamp,
      e.src_ip,
      e.dst_ip,
      `"${e.country}"`,
      `"${e.destination_asset}"`,
      e.attack_category,
      e.attack_prob,
      e.anomaly_score,
      e.baseline_flag,
      e.severity,
      e.risk_score,
      e.risk_level,
      e.mitre_technique.id,
      `"${e.mitre_technique.name}"`,
      `"${e.mitre_technique.tactic}"`,
      `"${e.recommended_action}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `soc_scored_events_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const getRiskBadge = (level: RiskLevel, score: number) => {
    switch (level) {
      case 'Critical':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            CRIT · {score}
          </span>
        );
      case 'High':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-orange-500/15 text-orange-300 border border-orange-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
            HIGH · {score}
          </span>
        );
      case 'Medium':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            MED · {score}
          </span>
        );
      case 'Low':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            LOW · {score}
          </span>
        );
    }
  };

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">
            Live Alerts Working Queue
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time analyst triage queue with dual ML inference, MITRE mappings, and containment playbooks
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-900 border border-slate-700 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-sky-400" />
            <span>Export Filtered CSV ({filteredEvents.length})</span>
          </button>
        </div>
      </div>

      {/* Search & Sort Controls Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-slate-900 rounded-xl border border-slate-800">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search IP, Event ID, Target Asset, MITRE Technique, Country..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-slate-950 border border-slate-800 text-slate-200 pl-9 pr-3 py-1.5 text-xs rounded-lg placeholder:text-slate-500 focus:outline-none focus:border-sky-500/50"
          />
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>Sort by:</span>
          <button
            onClick={() => handleSort('risk_score')}
            className={`px-2 py-1 rounded text-xs font-mono flex items-center gap-1 ${
              sortField === 'risk_score' ? 'bg-slate-800 text-sky-300 font-semibold' : 'hover:text-slate-200'
            }`}
          >
            Risk Score <ArrowUpDown className="w-3 h-3" />
          </button>
          <button
            onClick={() => handleSort('timestamp')}
            className={`px-2 py-1 rounded text-xs font-mono flex items-center gap-1 ${
              sortField === 'timestamp' ? 'bg-slate-800 text-sky-300 font-semibold' : 'hover:text-slate-200'
            }`}
          >
            Time <ArrowUpDown className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Main Sortable Alerts Table (Section 7 columns) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-3">Source IP</th>
                <th className="py-3 px-3">Destination Asset</th>
                <th className="py-3 px-3">Attack Category</th>
                <th className="py-3 px-3">Risk Level & Score</th>
                <th className="py-3 px-3">MITRE Technique</th>
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-4 text-right">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 text-xs font-sans">
                    No security alerts match the current query and filters. Try adjusting the search term or resetting the sidebar filters.
                  </td>
                </tr>
              ) : (
                paginatedEvents.map((evt) => {
                  const isSelected = selectedEventId === evt.event_id;
                  return (
                    <tr
                      key={evt.event_id}
                      onClick={() => onSelectEvent(evt)}
                      className={`hover:bg-slate-800/60 cursor-pointer transition-colors group ${
                        isSelected ? 'bg-sky-950/30 border-l-2 border-l-sky-500' : ''
                      }`}
                    >
                      <td className="py-3 px-4 font-semibold text-sky-400 whitespace-nowrap">
                        {evt.event_id}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap text-slate-300">
                        {evt.src_ip}
                        <span className="text-[10px] text-slate-500 ml-1.5 font-sans">({evt.country})</span>
                      </td>
                      <td className="py-3 px-3 text-slate-300 truncate max-w-[180px]">
                        {evt.destination_asset}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] border ${
                            evt.attack_category === 'DoS'
                              ? 'bg-sky-500/10 text-sky-300 border-sky-500/30'
                              : evt.attack_category === 'Probe'
                              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              : evt.attack_category === 'R2L'
                              ? 'bg-violet-500/10 text-violet-300 border-violet-500/30'
                              : evt.attack_category === 'U2R'
                              ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                              : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          }`}
                        >
                          {evt.attack_category}
                        </span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        {getRiskBadge(evt.risk_level, evt.risk_score)}
                      </td>
                      <td className="py-3 px-3 text-slate-300 max-w-[200px] truncate">
                        <span className="text-sky-300 font-semibold">{evt.mitre_technique.id}</span>{' '}
                        <span className="text-slate-400">{evt.mitre_technique.name}</span>
                      </td>
                      <td className="py-3 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <span className="text-sky-400 text-xs font-sans group-hover:underline flex items-center justify-end gap-1">
                          Inspect <ExternalLink className="w-3 h-3" />
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <span className="font-mono text-slate-200">{(currentPage - 1) * pageSize + 1}</span> to{' '}
            <span className="font-mono text-slate-200">
              {Math.min(currentPage * pageSize, filteredEvents.length)}
            </span>{' '}
            of <span className="font-mono text-slate-200">{filteredEvents.length}</span> events
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition-colors cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-xs">
              Page {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition-colors cursor-pointer"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
