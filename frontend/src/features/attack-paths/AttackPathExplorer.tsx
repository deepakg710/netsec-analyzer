import React, { useState, useEffect } from 'react';
import { AnalysisRun, AttackPath } from '../../types';
import {
  GitCommit,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  ShieldAlert,
  Server,
  Router as RouterIcon,
  Shield,
  Laptop,
  Terminal,
  Info,
  CheckCircle2,
  XCircle,
  Database,
  Upload,
  Zap
} from 'lucide-react';
import { apiClient } from '../../api/client';

interface AttackPathExplorerProps {
  run?: AnalysisRun;
  onOpenUploadConfigs?: () => void;
}

export const AttackPathExplorer: React.FC<AttackPathExplorerProps> = ({ run, onOpenUploadConfigs }) => {
  const pathList = run?.attack_paths || [];

  if (!run || pathList.length === 0) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50 text-slate-900">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600 shadow-sm">
          <Zap className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Attack Paths Computed</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Upload Cisco configurations or run an analysis on an active network to simulate multi-hop attack traversals and test zero-trust ACL boundaries across your topology.
        </p>
        <div className="mt-5 flex items-center gap-3">
          {onOpenUploadConfigs && (
            <button
              onClick={onOpenUploadConfigs}
              className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm transition-all flex items-center gap-2"
            >
              <Upload className="w-4 h-4" />
              <span>Import Configurations</span>
            </button>
          )}
        </div>
      </div>
    );
  }

  const [sourceEntity, setSourceEntity] = useState<string>(pathList[0]?.source_entity || '');
  const [targetEntity, setTargetEntity] = useState<string>(pathList[0]?.target_entity || '');
  const [currentPath, setCurrentPath] = useState<AttackPath | null>(pathList[0] || null);
  const [isCalculating, setIsCalculating] = useState(false);

  useEffect(() => {
    if (pathList.length > 0) {
      setSourceEntity(pathList[0].source_entity);
      setTargetEntity(pathList[0].target_entity);
      setCurrentPath(pathList[0]);
    }
  }, [run?.id]);

  const sourceOptions = Array.from(new Set(pathList.map((p) => p.source_entity)));
  const targetOptions = Array.from(new Set(pathList.map((p) => p.target_entity)));

  const handleAnalyze = async () => {
    if (!run) return;
    setIsCalculating(true);
    try {
      const res = await apiClient.calculateAttackPath(
        run.id,
        sourceEntity,
        targetEntity,
        `Assess reachability from ${sourceEntity} to ${targetEntity}`
      );
      setCurrentPath(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsCalculating(false);
    }
  };

  const isPathFound =
    currentPath?.status === 'PATH_FOUND' ||
    currentPath?.status === 'Potential path identified' ||
    (currentPath?.hops && currentPath.hops.length > 0 && currentPath.hops.every((h) => !h.action.includes('DENY') && !h.action.includes('BLOCKED')));

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header & Source/Target Query Toolbar matching Reference Screen 4 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <GitCommit className="w-6 h-6 text-blue-600" />
            Attack-Path Explorer
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Simulate multi-hop traversal across routers, switches, and firewalls to test zero-trust segmentation and ACL enforcement.
          </p>
        </div>
      </div>

      <div className="cyber-card p-5 bg-white border border-slate-200 shadow-xs flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4 w-full md:w-auto">
          {/* Source Selector */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">From (Source):</label>
            <select
              value={sourceEntity}
              onChange={(e) => {
                setSourceEntity(e.target.value);
                const matched = pathList.find((p) => p.source_entity === e.target.value);
                if (matched) setCurrentPath(matched);
              }}
              className="cyber-input py-1.5 text-xs w-64 bg-white text-slate-800"
            >
              {sourceOptions.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-400 hidden md:block mt-4" />

          {/* Target Selector */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">To (Target):</label>
            <select
              value={targetEntity}
              onChange={(e) => {
                setTargetEntity(e.target.value);
                const matched = pathList.find((p) => p.target_entity === e.target.value);
                if (matched) setCurrentPath(matched);
              }}
              className="cyber-input py-1.5 text-xs w-64 bg-white text-slate-800"
            >
              {targetOptions.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleAnalyze}
          disabled={isCalculating}
          className="w-full md:w-auto px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-bold tracking-wide shadow-sm transition-all flex items-center justify-center gap-2"
        >
          <GitCommit className="w-4 h-4" />
          <span>{isCalculating ? 'Tracing Path...' : 'Analyze'}</span>
        </button>
      </div>

      {/* 2. Visual Multi-Hop Node Sequence matching Reference Screen 4 */}
      <div className="cyber-card p-8 bg-white border border-slate-200 shadow-xs">
        <div className="flex items-center justify-start overflow-x-auto py-3 px-2 gap-4">
          {currentPath?.hops && currentPath.hops.length > 0 ? (
            currentPath.hops.map((hop, idx) => {
              const isLast = idx === currentPath.hops.length - 1;
              const isBlocked = hop.action.includes('DENY') || hop.action.includes('BLOCKED');
              return (
                <React.Fragment key={idx}>
                  <div className="flex flex-col items-center gap-2 shrink-0 min-w-[100px]">
                    <div
                      className={`w-12 h-12 rounded-xl border-2 flex items-center justify-center shadow-xs ${
                        isLast
                          ? isBlocked
                            ? 'bg-emerald-50 border-emerald-500'
                            : 'bg-red-50 border-red-500'
                          : 'bg-blue-50 border-blue-400'
                      }`}
                    >
                      {idx === 0 ? (
                        <Laptop className="w-6 h-6 text-blue-600" />
                      ) : isLast ? (
                        <Database className={`w-6 h-6 ${isBlocked ? 'text-emerald-600' : 'text-red-600'}`} />
                      ) : hop.action.includes('ACL') ? (
                        <Shield className="w-6 h-6 text-amber-600" />
                      ) : hop.from_node.toLowerCase().includes('r') ? (
                        <RouterIcon className="w-6 h-6 text-blue-600" />
                      ) : (
                        <Server className="w-6 h-6 text-blue-600" />
                      )}
                    </div>
                    <div className="text-center">
                      <div className="text-xs font-bold text-slate-900 truncate max-w-[110px]">{hop.from_node}</div>
                      <div className="text-[10px] text-slate-500 font-mono">{hop.egress_interface || hop.device_id}</div>
                    </div>
                  </div>
                  {!isLast && <ArrowRight className="w-5 h-5 text-blue-400 shrink-0" />}
                </React.Fragment>
              );
            })
          ) : (
            <div className="text-xs text-slate-500 p-4">No detailed hops recorded for this path query.</div>
          )}
        </div>
      </div>

      {/* 3. Lower Section: Path Details (Left) vs Issues Found (Right) matching Reference Screen 4 */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Path Details / Path Analysis (Col Span 6) */}
        <div className="lg:col-span-6 cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide">Path Details</h3>
            <span
              className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                isPathFound
                  ? 'bg-red-50 text-red-700 border border-red-200'
                  : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
              }`}
            >
              {isPathFound ? 'Potential Path Found' : 'Path Blocked by ACL'}
            </span>
          </div>

          <p className="text-xs text-slate-600 leading-relaxed">
            {currentPath?.status_summary || `Analysis evaluated path traversal from ${sourceEntity} to ${targetEntity}.`}
          </p>

          <div className="space-y-2 pt-2">
            <div className="font-bold text-xs text-slate-800">Path Steps:</div>
            <div className="space-y-1.5 text-xs text-slate-700 font-mono">
              {currentPath?.hops && currentPath.hops.length > 0 ? (
                currentPath.hops.map((hop, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between"
                  >
                    <span>
                      {idx + 1}. {hop.from_node} ➔ {hop.to_node} ({hop.action})
                    </span>
                    <span
                      className={`text-[10px] uppercase font-bold ${
                        hop.action.includes('DENY') || hop.action.includes('BLOCKED')
                          ? 'text-emerald-700'
                          : hop.action.includes('PERMIT')
                          ? 'text-amber-700'
                          : 'text-blue-700'
                      }`}
                    >
                      {hop.policy_applied || hop.action}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-slate-400 text-xs">No hop steps available.</div>
              )}
            </div>
          </div>
        </div>

        {/* Right: Key Observations / Issues Found (Col Span 6) */}
        <div className="lg:col-span-6 cyber-card p-6 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide">Key Observations</h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                  isPathFound
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}
              >
                Risk Level: {isPathFound ? 'High' : 'Low'}
              </span>
            </div>

            <div className="space-y-3">
              {currentPath?.key_observations && currentPath.key_observations.length > 0 ? (
                currentPath.key_observations.map((obs, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-red-50/70 border border-red-200 flex items-start gap-2.5 text-xs text-red-800"
                  >
                    <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold text-red-900">Security Observation {idx + 1}</div>
                      <div className="text-[11px] text-red-700/90 mt-0.5">{obs}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                  No critical traversal bypasses identified along this specific path.
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 p-3 rounded-xl bg-slate-50 border border-slate-200 text-[11px] text-slate-600 flex items-start gap-2">
            <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <span>
              <strong>Deterministic Traversal:</strong> NetSec Analyzer models Layer 3 routing LPM and hop-by-hop ingress/egress ACL rule evaluation to verify reachability.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
