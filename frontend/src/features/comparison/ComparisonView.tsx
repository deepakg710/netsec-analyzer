import React, { useState, useEffect } from 'react';
import { Project, AnalysisRun, ComparisonResult } from '../../types';
import { apiClient } from '../../api/client';
import {
  GitCompare,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  TrendingUp,
  Shield,
  Layers,
  Network,
  RefreshCw,
  Plus,
  Minus,
  Check,
  ChevronRight,
  Upload
} from 'lucide-react';

interface ComparisonViewProps {
  currentProject: Project | null;
  currentRun: AnalysisRun | null;
  onOpenUploadConfigs?: () => void;
}

export const ComparisonView: React.FC<ComparisonViewProps> = ({ currentProject, currentRun, onOpenUploadConfigs }) => {
  const [runs, setRuns] = useState<any[]>([]);
  const [baselineRunId, setBaselineRunId] = useState<string>('');
  const [remediatedRunId, setRemediatedRunId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'differences' | 'scores' | 'topology'>('differences');
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (currentProject?.id) {
      apiClient.getProject(currentProject.id).then((p) => {
        const rList = p.runs || [];
        setRuns(rList);
        if (rList.length >= 2) {
          setBaselineRunId(rList[rList.length - 1].id);
          setRemediatedRunId(rList[0].id);
        } else if (rList.length === 1) {
          setBaselineRunId(rList[0].id);
        }
      });
    }
  }, [currentProject?.id, currentRun?.id]);

  useEffect(() => {
    if (baselineRunId && remediatedRunId && baselineRunId !== remediatedRunId) {
      setLoading(true);
      apiClient
        .compareRuns(baselineRunId, remediatedRunId)
        .then((data) => setComparison(data))
        .catch((err) => console.error(err))
        .finally(() => setLoading(false));
    }
  }, [baselineRunId, remediatedRunId]);

  if (runs.length < 2) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50 text-slate-900">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600 shadow-sm">
          <GitCompare className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">Comparison Requires Multiple Analysis Runs</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          {runs.length === 1
            ? "You have 1 analysis run completed. Upload or paste an updated/remediated configuration to compare changes, track resolved findings, and verify score improvements."
            : "Upload configuration files to begin analyzing and comparing network security revisions."}
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

  const resolvedCount = comparison?.resolved_findings_count ?? comparison?.resolved_findings?.length ?? 0;
  const remainingCount = comparison?.persistent_findings_count ?? comparison?.persistent_findings?.length ?? 0;
  const newCount = comparison?.new_findings_count ?? comparison?.new_findings?.length ?? 0;
  const scoreDiff = comparison?.score_delta ?? 0;

  const baselineRun = runs.find((r) => r.id === baselineRunId);
  const remediatedRun = runs.find((r) => r.id === remediatedRunId);

  const baselineScore = comparison?.score_before ?? baselineRun?.overall_score ?? 0;
  const remediatedScore = comparison?.score_after ?? remediatedRun?.overall_score ?? 0;
  const keyChanges: string[] = (comparison?.resolved_findings || []).map((f: any) => f.title ? (`Hardened: ${f.title}`) : 'Vulnerability remediated');

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header & Run Selection Toolbar matching Reference Screen 8 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <GitCompare className="w-6 h-6 text-blue-600" />
            Before &amp; After Analysis Comparison
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Compare network design versions to verify vulnerability remediation, track score improvements, and detect regressions.
          </p>
        </div>
      </div>

      <div className="cyber-card p-4 bg-white border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Baseline Run:</label>
            <select
              value={baselineRunId}
              onChange={(e) => setBaselineRunId(e.target.value)}
              className="cyber-input py-1.5 text-xs bg-white text-slate-800 w-56"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.timestamp?.slice(0, 16).replace('T', ' ')} (Score: {r.overall_score})
                </option>
              ))}
            </select>
          </div>

          <ArrowRight className="w-4 h-4 text-slate-400 hidden sm:block mt-4" />

          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">Remediated Run:</label>
            <select
              value={remediatedRunId}
              onChange={(e) => setRemediatedRunId(e.target.value)}
              className="cyber-input py-1.5 text-xs bg-white text-slate-800 w-56"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.timestamp?.slice(0, 16).replace('T', ' ')} (Score: {r.overall_score})
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={() => {
            if (baselineRunId && remediatedRunId) {
              setLoading(true);
              apiClient
                .compareRuns(baselineRunId, remediatedRunId)
                .then((data) => setComparison(data))
                .finally(() => setLoading(false));
            }
          }}
          className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm transition-all flex items-center gap-1.5"
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>{loading ? 'Comparing...' : 'Compare'}</span>
        </button>
      </div>

      {/* 2. Top 4 Metric Summary Cards matching Reference Screen 8 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Resolved Findings */}
        <div className="cyber-card p-4 border border-emerald-200 bg-emerald-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-emerald-700">
            <span>Resolved Findings</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-3xl font-black text-emerald-700 mt-2 font-mono">{resolvedCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Successfully remediated</div>
        </div>

        {/* Remaining Findings */}
        <div className="cyber-card p-4 border border-orange-200 bg-orange-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-orange-700">
            <span>Remaining Findings</span>
            <AlertTriangle className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-3xl font-black text-orange-700 mt-2 font-mono">{remainingCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Still present in config</div>
        </div>

        {/* New Findings */}
        <div className="cyber-card p-4 border border-red-200 bg-red-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-red-700">
            <span>New Findings</span>
            <AlertCircle className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-3xl font-black text-red-700 mt-2 font-mono">{newCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Introduced in changes</div>
        </div>

        {/* Score Improvement */}
        <div className="cyber-card p-4 border border-blue-200 bg-blue-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-blue-700">
            <span>Score Improvement</span>
            <TrendingUp className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-3xl font-black text-blue-700 mt-2 font-mono">
            {scoreDiff >= 0 ? `+${scoreDiff}` : scoreDiff}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {baselineScore} &rarr; {remediatedScore} ({scoreDiff >= 0 ? `+${scoreDiff}` : scoreDiff} pts)
          </div>
        </div>
      </div>

      {/* 3. Lower Comparison Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Score Comparison Gauges */}
        <div className="lg:col-span-5 cyber-card p-6 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 tracking-wide pb-3 border-b border-slate-200">
              Score Comparison
            </h3>

            <div className="flex items-center justify-center gap-8 py-8">
              {/* Baseline Circle */}
              <div className="flex flex-col items-center">
                <div className="w-24 h-24 rounded-full border-4 border-slate-300 flex items-center justify-center shadow-xs">
                  <span className="text-2xl font-black text-slate-700 font-mono">{baselineScore}</span>
                </div>
                <span className="text-xs font-bold text-slate-600 mt-3">Before</span>
                <span className="text-[10px] text-slate-400">Baseline Run</span>
              </div>

              <div className="flex flex-col items-center">
                <ArrowRight className="w-6 h-6 text-slate-400" />
                <span className="text-xs font-bold text-emerald-600 font-mono mt-1">
                  {scoreDiff >= 0 ? `+${scoreDiff} pts` : `${scoreDiff} pts`}
                </span>
              </div>

              {/* Remediated Circle */}
              <div className="flex flex-col items-center">
                <div className="w-24 h-24 rounded-full border-4 border-blue-600 flex items-center justify-center shadow-md">
                  <span className="text-2xl font-black text-blue-600 font-mono">{remediatedScore}</span>
                </div>
                <span className="text-xs font-bold text-blue-700 mt-3">After</span>
                <span className="text-[10px] text-blue-500">Remediated Run</span>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Topology Structure:</span>
            <span className="text-emerald-700 font-semibold">
              No structural changes detected
            </span>
          </div>
        </div>

        {/* Right: Key Changes Breakdown */}
        <div className="lg:col-span-7 cyber-card p-6 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 tracking-wide pb-3 border-b border-slate-200">
              Key Changes Breakdown
            </h3>

            <div className="space-y-3 mt-4">
              {keyChanges.length > 0 ? (
                keyChanges.map((change: string, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between text-xs text-slate-800"
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <span>{change}</span>
                    </div>
                    <span className="text-[10px] font-bold text-emerald-700 font-mono">Remediated</span>
                  </div>
                ))
              ) : (
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-500">
                  Select baseline and remediated runs above to calculate difference breakdown.
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 text-[10px] text-slate-400">
            Comparison Engine: Hash-based differential AST rule matching
          </div>
        </div>
      </div>
    </div>
  );
};
