import React, { useState, useMemo } from 'react';
import { Globe, MapPin, ShieldAlert, Info, ExternalLink } from 'lucide-react';
import { ScoredEvent } from '../types/threat';

interface ThreatMapViewProps {
  events: ScoredEvent[];
  onSelectEvent: (event: ScoredEvent) => void;
}

export const ThreatMapView: React.FC<ThreatMapViewProps> = ({ events, onSelectEvent }) => {
  const [hoveredEvent, setHoveredEvent] = useState<ScoredEvent | null>(null);
  const [selectedCountryFilter, setSelectedCountryFilter] = useState<string | null>(null);

  // Top 10 Source Countries Aggregation (Section 7 requirement)
  const top10Countries = useMemo(() => {
    const counts: Record<string, { total: number; attacks: number; avgRisk: number; country_code: string }> = {};

    events.forEach((e) => {
      if (!counts[e.country]) {
        counts[e.country] = { total: 0, attacks: 0, avgRisk: 0, country_code: e.country_code };
      }
      counts[e.country].total += 1;
      if (e.attack_category !== 'Normal') counts[e.country].attacks += 1;
      counts[e.country].avgRisk += e.risk_score;
    });

    return Object.entries(counts)
      .map(([country, stats]) => ({
        country,
        country_code: stats.country_code,
        total: stats.total,
        attacks: stats.attacks,
        avgRisk: Math.round((stats.avgRisk / stats.total) * 10) / 10,
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);
  }, [events]);

  const mapEvents = useMemo(() => {
    if (!selectedCountryFilter) return events;
    return events.filter((e) => e.country === selectedCountryFilter);
  }, [events, selectedCountryFilter]);

  // Convert lat/lon to SVG coordinates (Equirectangular Projection)
  // viewBox: 0 0 1000 500
  // x = (lon + 180) * (1000 / 360)
  // y = (90 - lat) * (500 / 180)
  const projectCoords = (lat: number, lon: number) => {
    const x = ((lon + 180) * 1000) / 360;
    const y = ((90 - lat) * 500) / 180;
    return { x, y };
  };

  const getMarkerColor = (category: string) => {
    switch (category) {
      case 'DoS':
        return '#38bdf8'; // sky-400
      case 'Probe':
        return '#fbbf24'; // amber-400
      case 'R2L':
        return '#c084fc'; // violet-400
      case 'U2R':
        return '#fb7185'; // rose-400
      case 'Normal':
      default:
        return '#34d399'; // emerald-400
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title & Note on Geolocation (Section 7 requirement) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Globe className="w-5 h-5 text-sky-400" />
            Global Attack Origins & Geolocation Map
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time geospatial scatter of attack origins sized by risk score and classified by NSL-KDD attack vectors
          </p>
        </div>

        {/* Note on data source badge as required by Section 7 */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
          <Info className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          <span>Locations derived from MaxMind GeoLite2 & IP heuristics (Simulated Telemetry)</span>
        </div>
      </div>

      {/* Main Interactive Threat Map Canvas */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-4">
            <span className="font-semibold text-slate-200">Global Threat Scatter</span>
            <span className="text-slate-500 font-mono">
              Plotting {mapEvents.length} origin vectors {selectedCountryFilter ? `in ${selectedCountryFilter}` : ''}
            </span>
          </div>

          {selectedCountryFilter && (
            <button
              onClick={() => setSelectedCountryFilter(null)}
              className="text-[11px] font-mono text-sky-400 hover:underline"
            >
              Reset Country Filter (Show All)
            </button>
          )}

          {/* Severity Color Legend */}
          <div className="hidden md:flex items-center gap-3 text-[11px] font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
              <span className="text-slate-400">DoS</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
              <span className="text-slate-400">Probe</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-violet-400" />
              <span className="text-slate-400">R2L</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
              <span className="text-slate-400">U2R</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              <span className="text-slate-400">Normal</span>
            </div>
          </div>
        </div>

        {/* SVG World Map */}
        <div className="relative w-full aspect-[2/1] bg-[#030712] rounded-lg border border-slate-800/80 overflow-hidden">
          <svg className="w-full h-full" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet">
            {/* Latitude / Longitude Subtle Grid Lines */}
            <line x1="0" y1="125" x2="1000" y2="125" stroke="#1e293b" strokeDasharray="3 3" strokeWidth="0.5" />
            <line x1="0" y1="250" x2="1000" y2="250" stroke="#334155" strokeWidth="0.8" />
            <line x1="0" y1="375" x2="1000" y2="375" stroke="#1e293b" strokeDasharray="3 3" strokeWidth="0.5" />
            <line x1="250" y1="0" x2="250" y2="500" stroke="#1e293b" strokeDasharray="3 3" strokeWidth="0.5" />
            <line x1="500" y1="0" x2="500" y2="500" stroke="#334155" strokeWidth="0.8" />
            <line x1="750" y1="0" x2="750" y2="500" stroke="#1e293b" strokeDasharray="3 3" strokeWidth="0.5" />

            {/* Stylized Continents Outlines */}
            <g fill="#0f172a" stroke="#1e293b" strokeWidth="1" opacity="0.8">
              {/* North America */}
              <path d="M 120 70 L 280 60 L 320 140 L 260 210 L 190 260 L 160 230 L 140 180 Z" />
              {/* South America */}
              <path d="M 270 260 L 360 270 L 380 340 L 320 450 L 290 400 L 270 320 Z" />
              {/* Europe */}
              <path d="M 460 70 L 580 60 L 590 140 L 530 180 L 470 160 L 450 110 Z" />
              {/* Africa */}
              <path d="M 460 180 L 580 180 L 610 270 L 560 410 L 480 370 L 450 250 Z" />
              {/* Asia */}
              <path d="M 590 60 L 890 70 L 870 190 L 760 270 L 660 240 L 600 160 Z" />
              {/* Australia */}
              <path d="M 780 330 L 910 330 L 890 430 L 800 420 Z" />
            </g>

            {/* Threat Origin Points Sized by Risk Score */}
            {mapEvents.map((evt) => {
              const { x, y } = projectCoords(evt.lat, evt.lon);
              // Radius proportional to risk score (from 3px up to 12px)
              const radius = Math.max(3.5, (evt.risk_score / 100) * 11);
              const color = getMarkerColor(evt.attack_category);
              const isHovered = hoveredEvent?.event_id === evt.event_id;

              return (
                <g key={evt.event_id} className="cursor-pointer">
                  {/* Subtle Pulse for Critical Events */}
                  {evt.risk_level === 'Critical' && (
                    <circle
                      cx={x}
                      cy={y}
                      r={radius * 1.8}
                      fill={color}
                      opacity="0.25"
                      className="animate-ping"
                    />
                  )}

                  <circle
                    cx={x}
                    cy={y}
                    r={isHovered ? radius + 2 : radius}
                    fill={color}
                    fillOpacity={isHovered ? 1.0 : 0.75}
                    stroke="#ffffff"
                    strokeWidth={isHovered ? 1.5 : 0.5}
                    onMouseEnter={() => setHoveredEvent(evt)}
                    onMouseLeave={() => setHoveredEvent(null)}
                    onClick={() => onSelectEvent(evt)}
                  />
                </g>
              );
            })}
          </svg>

          {/* Interactive Tooltip Card */}
          {hoveredEvent && (
            <div
              className="absolute pointer-events-none z-30 p-3 rounded-lg bg-slate-950/95 border border-slate-700 shadow-xl text-xs space-y-1 backdrop-blur-md"
              style={{
                left: `${Math.min(75, Math.max(10, (projectCoords(hoveredEvent.lat, hoveredEvent.lon).x / 1000) * 100))}%`,
                top: `${Math.min(75, Math.max(10, (projectCoords(hoveredEvent.lat, hoveredEvent.lon).y / 500) * 100))}%`,
              }}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono font-bold text-sky-400">{hoveredEvent.src_ip}</span>
                <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                  {hoveredEvent.country}
                </span>
              </div>
              <div className="text-slate-300">
                Target: <span className="text-slate-100 font-mono">{hoveredEvent.destination_asset}</span>
              </div>
              <div className="flex items-center justify-between gap-3 text-[11px]">
                <span className="text-slate-400">Attack: {hoveredEvent.attack_category}</span>
                <span className="font-mono font-bold text-rose-400">Risk: {hoveredEvent.risk_score}</span>
              </div>
              <p className="text-[10px] text-sky-400 italic">Click node to inspect alert</p>
            </div>
          )}
        </div>
      </div>

      {/* Top 10 Source Countries Bar Chart (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Top 10 Attack Source Geographies
            </h3>
            <p className="text-[11px] text-slate-400">
              Aggregated frequency of inbound intrusion attempts by originating country
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">MaxMind GeoLite2 Ingestion</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {top10Countries.map((c, idx) => {
            const maxCount = top10Countries[0].total || 1;
            const pct = (c.total / maxCount) * 100;
            const isFilterActive = selectedCountryFilter === c.country;

            return (
              <div
                key={c.country}
                onClick={() => setSelectedCountryFilter(isFilterActive ? null : c.country)}
                className={`p-3 rounded-lg border transition-all cursor-pointer ${
                  isFilterActive
                    ? 'bg-sky-500/10 border-sky-500/40'
                    : 'bg-slate-950/70 border-slate-800/80 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 font-mono text-[10px] w-4">{idx + 1}.</span>
                    <span className="font-semibold text-slate-200">{c.country}</span>
                    <span className="text-[10px] font-mono text-slate-500">[{c.country_code}]</span>
                  </div>
                  <div className="flex items-center gap-3 font-mono text-xs">
                    <span className="text-slate-400">{c.attacks} attacks</span>
                    <span className="text-sky-400 font-bold">{c.total} total</span>
                  </div>
                </div>

                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="bg-sky-500 h-full rounded-full transition-all duration-300"
                    style={{ width: `${Math.max(5, pct)}%` }}
                  />
                </div>

                <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-500">
                  <span>Avg Risk Score: <strong className="text-slate-300 font-mono">{c.avgRisk}</strong></span>
                  <span className="text-sky-400 text-[10px]">{isFilterActive ? 'Active Filter' : 'Click to filter map'}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
