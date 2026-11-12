import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar, PageView } from './components/Sidebar';
import { Footer } from './components/Footer';
import { AlertDetailDrawer } from './components/AlertDetailDrawer';
import { PythonScriptsModal } from './components/PythonScriptsModal';

// Views
import { OverviewView } from './views/OverviewView';
import { LiveAlertsView } from './views/LiveAlertsView';
import { ThreatMapView } from './views/ThreatMapView';
import { AttackCoverageView } from './views/AttackCoverageView';
import { ThreatAnalyzerView } from './views/ThreatAnalyzerView';
import { ModelPerformanceView } from './views/ModelPerformanceView';
import { SimulateTrafficView } from './views/SimulateTrafficView';
import { SettingsView } from './views/SettingsView';

// Core Data & Types
import { INITIAL_SCORED_EVENTS, generateSyntheticEvents } from './data/initialEvents';
import { DEFAULT_SETTINGS, calculateRiskScore, getRiskLevel } from './engine/scoringEngine';
import { ScoredEvent, AttackCategory, RiskLevel, SettingsConfig } from './types/threat';

export default function App() {
  const [activePage, setActivePage] = useState<PageView>('overview');
  const [events, setEvents] = useState<ScoredEvent[]>(INITIAL_SCORED_EVENTS);
  const [selectedEvent, setSelectedEvent] = useState<ScoredEvent | null>(null);
  const [settings, setSettings] = useState<SettingsConfig>(DEFAULT_SETTINGS);
  const [isPythonModalOpen, setIsPythonModalOpen] = useState(false);
  const [isSimulatingQuick, setIsSimulatingQuick] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);

  // Global Filter State (Section 7 Global Elements requirement)
  const [selectedSeverities, setSelectedSeverities] = useState<AttackCategory[]>([
    'DoS',
    'Probe',
    'R2L',
    'U2R',
    'Normal',
  ]);
  const [selectedRiskLevel, setSelectedRiskLevel] = useState<RiskLevel | 'All'>('All');
  const [selectedBatch, setSelectedBatch] = useState<string>('all');

  // Real-time streaming simulation effect
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const newBurst = generateSyntheticEvents(1, Date.now() % 100000);
      setEvents((prev) => [newBurst[0], ...prev.slice(0, 299)]);
    }, 3500);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // Handle re-scoring when settings update
  const handleUpdateSettings = useCallback((newSettings: SettingsConfig) => {
    setSettings(newSettings);
    // Recalculate risk scores for existing events based on new weights and thresholds
    setEvents((prev) =>
      prev.map((e) => {
        const score = calculateRiskScore(e.attack_prob, e.severity, e.asset_criticality, newSettings);
        const level = getRiskLevel(score, newSettings);
        return {
          ...e,
          risk_score: score,
          risk_level: level,
        };
      })
    );
  }, []);

  // Quick simulate +25 events
  const handleQuickSimulate = async () => {
    setIsSimulatingQuick(true);
    await new Promise((r) => setTimeout(r, 600));
    const newBatch = generateSyntheticEvents(25, Date.now() % 50000);
    setEvents((prev) => [...newBatch, ...prev]);
    setIsSimulatingQuick(false);
  };

  const handleAddEvents = (newEvents: ScoredEvent[]) => {
    setEvents((prev) => [...newEvents, ...prev]);
  };

  // Filter events based on sidebar controls
  const filteredEvents = useMemo(() => {
    const now = Date.now();

    return events.filter((e) => {
      // 1. Severity filter
      if (!selectedSeverities.includes(e.attack_category)) return false;

      // 2. Risk level filter
      if (selectedRiskLevel !== 'All' && e.risk_level !== selectedRiskLevel) return false;

      // 3. Batch time filter
      if (selectedBatch === 'last_1h') {
        const ageHours = (now - new Date(e.timestamp).getTime()) / (1000 * 60 * 60);
        if (ageHours > 1) return false;
      } else if (selectedBatch === 'last_6h') {
        const ageHours = (now - new Date(e.timestamp).getTime()) / (1000 * 60 * 60);
        if (ageHours > 6) return false;
      } else if (selectedBatch === 'last_24h') {
        const ageHours = (now - new Date(e.timestamp).getTime()) / (1000 * 60 * 60);
        if (ageHours > 24) return false;
      }

      return true;
    });
  }, [events, selectedSeverities, selectedRiskLevel, selectedBatch]);

  const handleToggleSeverity = (cat: AttackCategory) => {
    setSelectedSeverities((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const handleResetFilters = () => {
    setSelectedSeverities(['DoS', 'Probe', 'R2L', 'U2R', 'Normal']);
    setSelectedRiskLevel('All');
    setSelectedBatch('all');
  };

  const criticalAlertsCount = useMemo(() => {
    return filteredEvents.filter((e) => e.risk_level === 'Critical').length;
  }, [filteredEvents]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Top Header */}
      <Header
        eventCount={filteredEvents.length}
        criticalCount={criticalAlertsCount}
        onQuickSimulate={handleQuickSimulate}
        onOpenPythonModal={() => setIsPythonModalOpen(true)}
        isSimulating={isSimulatingQuick}
      />

      {/* Main Workspace: Sidebar + Swappable Viewport */}
      <div className="flex-1 flex overflow-hidden">
        {/* Persistent SOC Sidebar */}
        <Sidebar
          activePage={activePage}
          onPageChange={setActivePage}
          selectedSeverities={selectedSeverities}
          onToggleSeverity={handleToggleSeverity}
          selectedRiskLevel={selectedRiskLevel}
          onSelectRiskLevel={setSelectedRiskLevel}
          selectedBatch={selectedBatch}
          onSelectBatch={setSelectedBatch}
          onResetFilters={handleResetFilters}
          isStreaming={isStreaming}
          onToggleStreaming={() => setIsStreaming((prev) => !prev)}
        />

        {/* Dynamic Page Viewport */}
        <main className="flex-1 overflow-y-auto bg-slate-950/60 pb-12">
          {activePage === 'overview' && (
            <OverviewView
              events={filteredEvents}
              onSelectEvent={setSelectedEvent}
              onNavigateToAlerts={() => setActivePage('alerts')}
            />
          )}

          {activePage === 'alerts' && (
            <LiveAlertsView
              events={filteredEvents}
              onSelectEvent={setSelectedEvent}
              selectedEventId={selectedEvent?.event_id}
            />
          )}

          {activePage === 'threat-map' && (
            <ThreatMapView
              events={filteredEvents}
              onSelectEvent={setSelectedEvent}
            />
          )}

          {activePage === 'attack-coverage' && (
            <AttackCoverageView
              events={filteredEvents}
              onSelectEvent={setSelectedEvent}
            />
          )}

          {activePage === 'threat-analyzer' && (
            <ThreatAnalyzerView settings={settings} />
          )}

          {activePage === 'model-performance' && (
            <ModelPerformanceView />
          )}

          {activePage === 'simulate' && (
            <SimulateTrafficView
              onAddEvents={handleAddEvents}
              onNavigateToAlerts={() => setActivePage('alerts')}
              settings={settings}
            />
          )}

          {activePage === 'settings' && (
            <SettingsView
              settings={settings}
              onUpdateSettings={handleUpdateSettings}
            />
          )}
        </main>
      </div>

      {/* Footer */}
      <Footer />

      {/* Detail Inspector Drawer (triggered on alert click in Live Alerts or Overview) */}
      <AlertDetailDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* Python Scripts Viewer Modal */}
      <PythonScriptsModal
        isOpen={isPythonModalOpen}
        onClose={() => setIsPythonModalOpen(false)}
      />
    </div>
  );
}
