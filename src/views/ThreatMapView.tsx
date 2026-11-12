import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Globe,
  MapPin,
  ShieldAlert,
  Info,
  ExternalLink,
  Navigation,
  Compass,
  Radio,
  Layers,
  Crosshair,
  AlertOctagon,
  Radar,
  Eye,
} from 'lucide-react';
import { APIProvider, Map as GoogleMap, AdvancedMarker, InfoWindow } from '@vis.gl/react-google-maps';
import { ScoredEvent } from '../types/threat';

interface ThreatMapViewProps {
  events: ScoredEvent[];
  onSelectEvent: (event: ScoredEvent) => void;
  apiKey?: string;
}

interface MapStyleRule {
  elementType?: string;
  featureType?: string;
  stylers: Array<Record<string, string | number>>;
}

// Dark tactical map style for SOC aesthetic
const DARK_SOC_MAP_STYLES: MapStyleRule[] = [
  { elementType: 'geometry', stylers: [{ color: '#090d16' }] },
  { elementType: 'labels.text.stroke', stylers: [{ color: '#090d16' }] },
  { elementType: 'labels.text.fill', stylers: [{ color: '#64748b' }] },
  { featureType: 'administrative.locality', elementType: 'labels.text.fill', stylers: [{ color: '#94a3b8' }] },
  { featureType: 'poi', stylers: [{ visibility: 'off' }] },
  { featureType: 'road', elementType: 'geometry', stylers: [{ color: '#172033' }] },
  { featureType: 'road', elementType: 'geometry.stroke', stylers: [{ color: '#0f172a' }] },
  { featureType: 'road.highway', elementType: 'geometry', stylers: [{ color: '#1e293b' }] },
  { featureType: 'road.highway', elementType: 'geometry.stroke', stylers: [{ color: '#090d16' }] },
  { featureType: 'transit', stylers: [{ visibility: 'off' }] },
  { featureType: 'water', elementType: 'geometry', stylers: [{ color: '#020617' }] },
  { featureType: 'water', elementType: 'labels.text.fill', stylers: [{ color: '#334155' }] },
];

// Haversine formula to compute distance in km
function calculateDistanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

export const ThreatMapView: React.FC<ThreatMapViewProps> = ({ events, onSelectEvent, apiKey = '' }) => {
  const [activeMarkerEvent, setActiveMarkerEvent] = useState<ScoredEvent | null>(null);
  const [selectedCountryFilter, setSelectedCountryFilter] = useState<string | null>(null);
  const [mapType, setMapType] = useState<'roadmap' | 'satellite' | 'hybrid'>('roadmap');

  // Real-time Analyst Geolocation state
  const [analystLocation, setAnalystLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [isLocating, setIsLocating] = useState<boolean>(false);
  const [geoError, setGeoError] = useState<string | null>(null);

  // Map view controls
  const [mapCenter, setMapCenter] = useState<{ lat: number; lng: number }>({ lat: 25, lng: 10 });
  const [mapZoom, setMapZoom] = useState<number>(2);

  // Top 10 Source Countries Aggregation
  const top10Countries = useMemo(() => {
    const counts: Record<string, { total: number; attacks: number; avgRisk: number; country_code: string; lat: number; lon: number }> = {};

    events.forEach((e) => {
      if (!counts[e.country]) {
        counts[e.country] = {
          total: 0,
          attacks: 0,
          avgRisk: 0,
          country_code: e.country_code,
          lat: e.lat,
          lon: e.lon,
        };
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
        lat: stats.lat,
        lon: stats.lon,
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);
  }, [events]);

  const mapEvents = useMemo(() => {
    if (!selectedCountryFilter) return events;
    return events.filter((e) => e.country === selectedCountryFilter);
  }, [events, selectedCountryFilter]);

  // Find closest attack event to analyst if geolocation is active
  const closestThreat = useMemo<{ event: ScoredEvent; distanceKm: number } | null>(() => {
    if (!analystLocation || mapEvents.length === 0) return null;
    let closest: { event: ScoredEvent; distanceKm: number } | null = null;

    mapEvents.forEach((evt) => {
      if (evt.attack_category === 'Normal') return;
      const d = calculateDistanceKm(analystLocation.lat, analystLocation.lng, evt.lat, evt.lon);
      if (!closest || d < closest.distanceKm) {
        closest = { event: evt, distanceKm: d };
      }
    });

    return closest;
  }, [analystLocation, mapEvents]);

  // Request real-time analyst geolocation from the browser
  const handleDetectAnalystLocation = () => {
    setIsLocating(true);
    setGeoError(null);

    if (!('geolocation' in navigator)) {
      setGeoError('Geolocation API not supported by this browser.');
      setIsLocating(false);
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords;
        setAnalystLocation({ lat: latitude, lng: longitude });
        setMapCenter({ lat: latitude, lng: longitude });
        setMapZoom(4);
        setIsLocating(false);
      },
      (err) => {
        console.warn('Geolocation lookup notice:', err.message);
        // Fallback default coordinate (e.g. SOC Headquarters / Frankfurt datacenter) if denied
        setAnalystLocation({ lat: 50.1109, lng: 8.6821 });
        setGeoError('Location permission denied or unavailable. Centered on SOC HQ (Frankfurt).');
        setIsLocating(false);
      },
      { timeout: 8000, enableHighAccuracy: true }
    );
  };

  const handleFocusCountry = (c: (typeof top10Countries)[0]) => {
    if (selectedCountryFilter === c.country) {
      setSelectedCountryFilter(null);
      setMapCenter({ lat: 25, lng: 10 });
      setMapZoom(2);
    } else {
      setSelectedCountryFilter(c.country);
      setMapCenter({ lat: c.lat, lng: c.lon });
      setMapZoom(4);
    }
  };

  const getSeverityColor = (category: string) => {
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
      {/* Title & Geolocation Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Globe className="w-5 h-5 text-sky-400" />
            <span>Real-Time Geospatial Threat & Attack Origin Map</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Live Google Maps telemetry plotting active intrusion origins, analyst proximity, and real-time IP threat coordinates
          </p>
        </div>

        {/* Live Controls: Geolocation button & Map Type switch */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Real-time Analyst Position Detector */}
          <button
            onClick={handleDetectAnalystLocation}
            disabled={isLocating}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border transition-all cursor-pointer ${
              analystLocation
                ? 'bg-sky-500/15 text-sky-300 border-sky-500/40'
                : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
            }`}
            title="Detect your physical location and calculate proximity to active threats"
          >
            <Crosshair className={`w-3.5 h-3.5 ${isLocating ? 'animate-spin text-sky-400' : 'text-sky-400'}`} />
            <span>
              {isLocating
                ? 'Locating SOC...'
                : analystLocation
                ? 'Analyst GPS Locked'
                : 'Detect My Location'}
            </span>
          </button>

          {/* Map Style Selector */}
          <div className="flex items-center rounded-lg bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
            <button
              onClick={() => setMapType('roadmap')}
              className={`px-2.5 py-1 rounded transition-colors ${
                mapType === 'roadmap' ? 'bg-slate-800 text-sky-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Tactical Dark
            </button>
            <button
              onClick={() => setMapType('satellite')}
              className={`px-2.5 py-1 rounded transition-colors ${
                mapType === 'satellite' ? 'bg-slate-800 text-sky-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Satellite
            </button>
            <button
              onClick={() => setMapType('hybrid')}
              className={`px-2.5 py-1 rounded transition-colors ${
                mapType === 'hybrid' ? 'bg-slate-800 text-sky-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hybrid
            </button>
          </div>
        </div>
      </div>

      {/* Geolocation Proximity Alert Banner (if analyst location detected) */}
      {analystLocation && closestThreat && (
        <div className="p-3.5 rounded-xl bg-sky-950/40 border border-sky-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs animate-in fade-in">
          <div className="flex items-center gap-2.5 text-slate-200">
            <div className="p-1.5 rounded-lg bg-sky-500/20 text-sky-400 shrink-0">
              <Radar className="w-4 h-4 animate-pulse" />
            </div>
            <div>
              <span className="font-semibold text-slate-100">Live Proximity Telemetry:</span>{' '}
              <span className="text-slate-300">
                Closest active adversary node is{' '}
                <strong className="text-rose-400 font-mono">{closestThreat.event.src_ip}</strong> ({closestThreat.event.country}),{' '}
                located{' '}
                <strong className="text-sky-300 font-mono">{closestThreat.distanceKm.toLocaleString()} km</strong> from your physical terminal.
              </span>
            </div>
          </div>

          <button
            onClick={() => onSelectEvent(closestThreat.event)}
            className="flex items-center gap-1 text-[11px] font-mono text-sky-400 hover:text-sky-300 hover:underline shrink-0"
          >
            <span>Triage Threat</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      )}

      {geoError && (
        <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
          <Info className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <span>{geoError}</span>
        </div>
      )}

      {/* Main Real-Time Google Maps Canvas Container */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-3">
            <span className="font-semibold text-slate-200">Live Telemetry Viewport</span>
            <span className="text-slate-500 font-mono">
              Plotting {mapEvents.length} active origin coordinates {selectedCountryFilter ? `(${selectedCountryFilter})` : ''}
            </span>
          </div>

          {/* Color Legend */}
          <div className="flex items-center gap-3 text-[11px] font-mono">
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
            {analystLocation && (
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
                <span className="text-cyan-300 font-semibold">Your Location</span>
              </div>
            )}
          </div>
        </div>

        {/* Real-time Google Maps Component (with explicit height per CF2) */}
        <div className="relative w-full h-[540px] rounded-lg overflow-hidden border border-slate-800/80 bg-[#060a12]">
          <APIProvider apiKey={apiKey} libraries={['marker']}>
            <GoogleMap
              // Mandatory internal attribution ID per Section 3 & 4
              internalUsageAttributionIds={['gmp_mcp_codeassist_v1_aistudio']}
              // Mandatory mapId for AdvancedMarkerElement per CF9
              mapId="DEMO_MAP_ID"
              style={{ width: '100%', height: '100%' }}
              defaultCenter={mapCenter}
              defaultZoom={mapZoom}
              center={mapCenter}
              zoom={mapZoom}
              onCameraChanged={(ev) => {
                setMapCenter(ev.detail.center);
                setMapZoom(ev.detail.zoom);
              }}
              mapTypeId={mapType}
              gestureHandling="greedy"
              disableDefaultUI={false}
              styles={mapType === 'roadmap' ? DARK_SOC_MAP_STYLES : undefined}
            >
              {/* Analyst Terminal Location Marker */}
              {analystLocation && (
                <AdvancedMarker
                  position={analystLocation}
                  title="Your SOC Terminal Physical Geolocation"
                >
                  <div className="relative flex items-center justify-center">
                    <div className="absolute w-10 h-10 rounded-full bg-cyan-500/20 animate-ping" />
                    <div className="absolute w-6 h-6 rounded-full bg-cyan-400/40" />
                    <div className="w-3.5 h-3.5 rounded-full bg-cyan-400 border-2 border-white shadow-lg shadow-cyan-500/50" />
                  </div>
                </AdvancedMarker>
              )}

              {/* Threat Origin Advanced Markers */}
              {mapEvents.map((evt) => {
                const color = getSeverityColor(evt.attack_category);
                // Diameter proportional to risk score (12px to 28px)
                const size = Math.max(12, Math.round((evt.risk_score / 100) * 24));
                const isCritical = evt.risk_level === 'Critical';

                return (
                  <AdvancedMarker
                    key={evt.event_id}
                    position={{ lat: evt.lat, lng: evt.lon }}
                    onClick={() => setActiveMarkerEvent(evt)}
                    title={`${evt.src_ip} (${evt.country}) - Risk: ${evt.risk_score}`}
                  >
                    <div
                      className="group relative flex items-center justify-center cursor-pointer transition-transform hover:scale-125"
                      style={{ width: size, height: size }}
                    >
                      {isCritical && (
                        <div
                          className="absolute inset-0 rounded-full animate-ping opacity-75"
                          style={{ backgroundColor: color }}
                        />
                      )}
                      <div
                        className="w-full h-full rounded-full border border-white/80 shadow-md"
                        style={{ backgroundColor: color }}
                      />
                    </div>
                  </AdvancedMarker>
                );
              })}

              {/* InfoWindow for clicked threat marker */}
              {activeMarkerEvent && (
                <InfoWindow
                  position={{ lat: activeMarkerEvent.lat, lng: activeMarkerEvent.lon }}
                  onCloseClick={() => setActiveMarkerEvent(null)}
                  maxWidth={320}
                >
                  <div className="p-2 text-slate-900 space-y-2 text-xs">
                    <div className="flex items-center justify-between border-b border-slate-200 pb-1.5">
                      <div className="font-mono font-bold text-sky-700 text-sm">
                        {activeMarkerEvent.src_ip}
                      </div>
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 font-semibold text-slate-700">
                        {activeMarkerEvent.country}
                      </span>
                    </div>

                    <div className="space-y-1 font-mono text-[11px] text-slate-700">
                      <div>
                        Target Asset:{' '}
                        <span className="font-semibold text-slate-900">
                          {activeMarkerEvent.destination_asset}
                        </span>
                      </div>
                      <div>
                        Category: <strong className="text-slate-900">{activeMarkerEvent.attack_category}</strong> (
                        {activeMarkerEvent.specific_attack})
                      </div>
                      <div className="flex items-center justify-between pt-1">
                        <span>Risk Score:</span>
                        <strong className="text-rose-600 font-bold text-xs">
                          {activeMarkerEvent.risk_score} / 100 ({activeMarkerEvent.risk_level})
                        </strong>
                      </div>
                      <div>
                        Coordinates: {activeMarkerEvent.lat.toFixed(2)}, {activeMarkerEvent.lon.toFixed(2)}
                      </div>
                      {analystLocation && (
                        <div className="text-sky-700 font-medium">
                          Distance to SOC:{' '}
                          {calculateDistanceKm(
                            analystLocation.lat,
                            analystLocation.lng,
                            activeMarkerEvent.lat,
                            activeMarkerEvent.lon
                          ).toLocaleString()}{' '}
                          km
                        </div>
                      )}
                    </div>

                    <div className="pt-2 border-t border-slate-200 flex items-center justify-between">
                      <span className="text-[10px] text-slate-500 font-sans">
                        MITRE: {activeMarkerEvent.mitre_technique.id}
                      </span>
                      <button
                        onClick={() => {
                          onSelectEvent(activeMarkerEvent);
                          setActiveMarkerEvent(null);
                        }}
                        className="px-2.5 py-1 text-[11px] font-semibold text-white bg-sky-700 hover:bg-sky-800 rounded transition-colors cursor-pointer"
                      >
                        Inspect Details
                      </button>
                    </div>
                  </div>
                </InfoWindow>
              )}
            </GoogleMap>
          </APIProvider>
        </div>
      </div>

      {/* Top 10 Source Countries Interactive Focus Cards (Section 7 requirement) */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-xs font-semibold text-slate-200">
              Top 10 Attack Source Geographies
            </h3>
            <p className="text-[11px] text-slate-400">
              Click any country to immediately pan and focus real-time map telemetry on that region
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">MaxMind GeoLite2 & IP Geolocation</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {top10Countries.map((c, idx) => {
            const maxCount = top10Countries[0].total || 1;
            const pct = (c.total / maxCount) * 100;
            const isFilterActive = selectedCountryFilter === c.country;

            return (
              <div
                key={c.country}
                onClick={() => handleFocusCountry(c)}
                className={`p-3 rounded-lg border transition-all cursor-pointer ${
                  isFilterActive
                    ? 'bg-sky-500/15 border-sky-500/50 shadow-md shadow-sky-500/10'
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
                  <span>
                    Avg Risk Score: <strong className="text-slate-300 font-mono">{c.avgRisk}</strong>
                  </span>
                  <span className="text-sky-400 text-[10px] font-medium flex items-center gap-1">
                    <MapPin className="w-3 h-3" />
                    <span>{isFilterActive ? 'Active Filter (Click to Reset)' : 'Focus On Map'}</span>
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
