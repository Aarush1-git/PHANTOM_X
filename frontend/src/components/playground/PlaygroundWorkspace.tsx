import React, { useState, useEffect } from 'react';
import {
  Terminal,
  RotateCcw,
  History,
  Play,
  Shield,
  Layers,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import {
  ScenarioInfo,
  PlaygroundTargetInfo,
  PlaygroundSession,
  PlaygroundResult,
} from '../../types/playground';
import { playgroundApi } from '../../services/playgroundApi';
import { ScenarioLibrary } from './ScenarioLibrary';
import { ScenarioDetailsPanel } from './ScenarioDetailsPanel';
import { TargetSelector } from './TargetSelector';
import { ExecutionPlanPreview } from './ExecutionPlanPreview';
import { ExecutionAuthorizationDialog } from './ExecutionAuthorizationDialog';
import { ExecutionProgress } from './ExecutionProgress';
import { PlaygroundResults } from './PlaygroundResults';
import { SessionHistory } from './SessionHistory';

export const PlaygroundWorkspace: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'playground' | 'history'>('playground');
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [targets, setTargets] = useState<PlaygroundTargetInfo[]>([]);
  const [sessions, setSessions] = useState<PlaygroundSession[]>([]);

  const [selectedScenario, setSelectedScenario] = useState<ScenarioInfo | null>(null);
  const [inspectingScenario, setInspectingScenario] = useState<ScenarioInfo | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<PlaygroundTargetInfo | null>(null);

  const [activeSession, setActiveSession] = useState<PlaygroundSession | null>(null);
  const [activeResult, setActiveResult] = useState<PlaygroundResult | null>(null);

  const [isAuthDialogOpen, setIsAuthDialogOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [isReplaying, setIsReplaying] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Load scenarios, targets, and history on mount
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [scenariosResp, targetsResp, historyResp] = await Promise.all([
        playgroundApi.listScenarios(),
        playgroundApi.listTargets(),
        playgroundApi.listSessions({ limit: 30 }),
      ]);
      setScenarios(scenariosResp.scenarios);
      setCategories(scenariosResp.categories);
      setTargets(targetsResp);
      setSessions(historyResp.items);

      // Auto-select synthetic target by default if none selected
      if (!selectedTarget && targetsResp.length > 0) {
        const synthetic = targetsResp.find((t) => t.is_synthetic);
        setSelectedTarget(synthetic || targetsResp[0]);
      }
      if (!selectedScenario && scenariosResp.scenarios.length > 0) {
        setSelectedScenario(scenariosResp.scenarios[0]);
      }
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || err.message || 'Failed to load playground data');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectScenario = (sc: ScenarioInfo) => {
    setSelectedScenario(sc);
    setActiveSession(null);
    setActiveResult(null);
  };

  const handleSelectTarget = (target: PlaygroundTargetInfo) => {
    setSelectedTarget(target);
    setActiveSession(null);
    setActiveResult(null);
  };

  // Create session
  const handlePrepareSession = async () => {
    if (!selectedScenario || !selectedTarget) return;
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const sess = await playgroundApi.createSession({
        application_id: selectedTarget.id,
        scenario_id: selectedScenario.id,
        notes: `Prepared via UI for target ${selectedTarget.name}`,
      });
      setActiveSession(sess);
      setActiveResult(null);
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || err.message || 'Failed to initialize session');
    } finally {
      setIsLoading(false);
    }
  };

  // Authorize session
  const handleConfirmAuthorization = async (notes?: string) => {
    if (!activeSession) return;
    try {
      const authorizedSession = await playgroundApi.authorizeSession(activeSession.id, {
        notes,
      });
      setActiveSession(authorizedSession);
      // Update in history list
      setSessions((prev) =>
        prev.map((s) => (s.id === authorizedSession.id ? authorizedSession : s))
      );
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || err.message || 'Authorization failed');
      throw err;
    }
  };

  // Execute session
  const handleExecuteSession = async () => {
    if (!activeSession) return;
    setIsExecuting(true);
    setErrorMessage(null);
    try {
      const res = await playgroundApi.executeSession(activeSession.id);
      setActiveResult(res);

      // Refresh session state
      const updatedSess = await playgroundApi.getSession(activeSession.id);
      setActiveSession(updatedSess);
      setSessions((prev) =>
        prev.map((s) => (s.id === updatedSess.id ? updatedSess : s))
      );
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || err.message || 'Execution error');
      // If blocked, reload session to inspect safety decisions
      try {
        const refreshed = await playgroundApi.getSession(activeSession.id);
        setActiveSession(refreshed);
      } catch {}
    } finally {
      setIsExecuting(false);
    }
  };

  // Replay session
  const handleReplaySession = async (sessionId?: string) => {
    const targetSessionId = sessionId || activeSession?.id;
    if (!targetSessionId) return;

    setIsReplaying(true);
    setErrorMessage(null);
    try {
      const childSession = await playgroundApi.replaySession(targetSessionId);
      setActiveSession(childSession);
      setActiveResult(null);
      // Match scenario and target
      const sc = scenarios.find((s) => s.id === childSession.scenario_id);
      if (sc) setSelectedScenario(sc);
      const tg = targets.find((t) => t.id === childSession.application_id);
      if (tg) setSelectedTarget(tg);

      // Prepend child session to history
      setSessions((prev) => [childSession, ...prev]);
      setActiveTab('playground');
    } catch (err: any) {
      setErrorMessage(err.response?.data?.detail || err.message || 'Replay initialization failed');
    } finally {
      setIsReplaying(false);
    }
  };

  // Select an existing historical session to inspect
  const handleSelectHistoricalSession = async (sess: PlaygroundSession) => {
    setActiveSession(sess);
    const sc = scenarios.find((s) => s.id === sess.scenario_id);
    if (sc) setSelectedScenario(sc);
    const tg = targets.find((t) => t.id === sess.application_id);
    if (tg) setSelectedTarget(tg);

    if (sess.status === 'COMPLETED' || sess.status === 'BLOCKED') {
      try {
        const res = await playgroundApi.getSessionResults(sess.id);
        setActiveResult(res);
      } catch {
        setActiveResult(null);
      }
    } else {
      setActiveResult(null);
    }
    setActiveTab('playground');
  };

  return (
    <div className="space-y-6">
      {/* Top Navigation Tabs */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('playground')}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'playground'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            <Play className="w-3.5 h-3.5" /> Active Playground
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === 'history'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            <History className="w-3.5 h-3.5" /> Session History ({sessions.length})
          </button>
        </div>

        <button
          type="button"
          onClick={loadInitialData}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
          title="Refresh Data"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Error Notice */}
      {errorMessage && (
        <div className="p-3 bg-red-950/30 border border-red-500/40 rounded-xl flex items-center justify-between text-xs text-red-200 animate-shake">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setErrorMessage(null)}
            className="text-slate-400 hover:text-slate-200 text-xs ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {activeTab === 'history' ? (
        <SessionHistory
          sessions={sessions}
          isLoading={isLoading}
          onSelectSession={handleSelectHistoricalSession}
          onReplaySession={(id) => handleReplaySession(id)}
        />
      ) : (
        <div className="space-y-6">
          {/* Active Lifecycle Progress if session exists */}
          {activeSession && (
            <ExecutionProgress session={activeSession} isExecuting={isExecuting} />
          )}

          {/* Results View if execution finished */}
          {activeResult && (
            <PlaygroundResults
              result={activeResult}
              onReplay={() => handleReplaySession()}
              isReplaying={isReplaying}
            />
          )}

          {/* Execution Plan Preview when session created and not completed */}
          {activeSession && !activeResult && (
            <ExecutionPlanPreview
              session={activeSession}
              onOpenAuthorizeModal={() => setIsAuthDialogOpen(true)}
              onExecuteNow={handleExecuteSession}
              isExecuting={isExecuting}
            />
          )}

          {/* Scenario & Target Setup Cards */}
          {!activeSession && (
            <div className="space-y-6">
              {/* Target Selector */}
              <TargetSelector
                targets={targets}
                selectedTarget={selectedTarget}
                onSelectTarget={handleSelectTarget}
              />

              {/* Scenario Library */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" /> Attack Scenario Library
                  </h3>
                  {selectedScenario && selectedTarget && (
                    <button
                      type="button"
                      onClick={handlePrepareSession}
                      className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-white shadow-md transition-colors"
                    >
                      <Play className="w-3.5 h-3.5" /> Initialize Test Session
                    </button>
                  )}
                </div>

                <ScenarioLibrary
                  scenarios={scenarios}
                  categories={categories}
                  selectedScenario={selectedScenario}
                  onSelectScenario={handleSelectScenario}
                  onViewDetails={(sc) => setInspectingScenario(sc)}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scenario Details Modal */}
      <ScenarioDetailsPanel
        scenario={inspectingScenario}
        onClose={() => setInspectingScenario(null)}
        onSelectAndConfigure={(sc) => {
          setSelectedScenario(sc);
          setInspectingScenario(null);
        }}
      />

      {/* Explicit Authorization Dialog */}
      <ExecutionAuthorizationDialog
        session={activeSession}
        onClose={() => setIsAuthDialogOpen(false)}
        onConfirmAuthorization={handleConfirmAuthorization}
      />
    </div>
  );
};
