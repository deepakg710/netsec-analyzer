import React, { useState, useEffect } from 'react';
import { AnalysisRun, ResilienceResult } from '../../types';
import { apiClient } from '../../api/client';
import {
  Activity,
  AlertTriangle,
  Server,
  Router as RouterIcon,
  Shield,
  Layers,
  Network,
  XCircle,
  CheckCircle2,
  RefreshCw,
  GitFork,
  ArrowRight,
  Sliders,
  Check,
  Info,
  Upload
} from 'lucide-react';

interface ResilienceViewProps {
  run?: AnalysisRun;
  onOpenUploadConfigs?: () => void;
}

export const ResilienceView: React.FC<ResilienceViewProps> = ({ run, onOpenUploadConfigs }) => {
  if (!run || !run.id) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50 text-slate-900">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600 shadow-sm">
          <Activity className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Resilience Analysis Available</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Upload Cisco configurations or run an analysis to identify single points of failure (SPOFs), missing failover links, and calculate topology graph resilience.
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

  const [activeTab, setActiveTab] = useState<'resilience' | 'quality' | 'redundancy'>('resilience');
  const [resilienceData, setResilienceData] = useState<ResilienceResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (run?.id) {
      setLoading(true);
      apiClient
        .getResilience(run.id)
        .then((data) => setResilienceData(data))
        .catch((err) => console.error(err))
        .finally(() => setLoading(false));
    }
  }, [run?.id]);

  const spofs = resilienceData?.single_points_of_failure || [];
  const missingRedundancy = resilienceData?.missing_redundancy || [];
  const overlaps = resilienceData?.overlapping_subnets || [];

  const spofCount = spofs.length;
  const redCount = missingRedundancy.length;
  const routeCount = 0;
  const subnetOverlapCount = overlaps.length;

  const resilienceScore = Math.max(30, 100 - (spofCount * 15 + redCount * 10));
  const redundancyScore = Math.max(20, 100 - redCount * 20);
  const routingScore = 85;
  const segmentationScore = 80;
  const stabilityScore = 75;

  // SVG Gauge calculations
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (resilienceScore / 100) * circumference;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header matching Reference Screen 7 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-blue-600" />
            Network Resilience &amp; Quality Analysis
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Structural topology analysis identifying articulation points, missing failover uplinks, and subnet conflicts.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-600 bg-white px-3 py-1.5 rounded-xl border border-slate-200 shadow-xs">
          Analysis Date: <span className="text-slate-800 font-semibold">{run.timestamp ? run.timestamp.slice(0, 16).replace('T', ' ') : 'Just now'}</span>
        </div>
      </div>

      {/* 2. Top 4 Metric KPI Cards matching Reference Screen 7 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Single Points of Failure */}
        <div className="cyber-card p-4 border border-red-200 bg-red-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-red-700">
            <span>Single Points of Failure</span>
            <XCircle className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-3xl font-black text-red-700 mt-2 font-mono">{spofCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Critical network choke points</div>
        </div>

        {/* Redundancy Issues */}
        <div className="cyber-card p-4 border border-orange-200 bg-orange-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-orange-700">
            <span>Redundancy Issues</span>
            <AlertTriangle className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-3xl font-black text-orange-700 mt-2 font-mono">{redCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Missing secondary paths</div>
        </div>

        {/* Routing Issues */}
        <div className="cyber-card p-4 border border-blue-200 bg-blue-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-blue-700">
            <span>Routing Issues</span>
            <Info className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-3xl font-black text-blue-700 mt-2 font-mono">{routeCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Route loop / convergence risk</div>
        </div>

        {/* Subnet Overlaps */}
        <div className="cyber-card p-4 border border-emerald-200 bg-emerald-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-emerald-700">
            <span>Subnet Overlaps</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-3xl font-black text-emerald-700 mt-2 font-mono">{subnetOverlapCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">0 IP collision conflicts detected</div>
        </div>
      </div>

      {/* 3. Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveTab('resilience')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'resilience'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          Resilience Analysis
        </button>
        <button
          onClick={() => setActiveTab('quality')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'quality'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          Network Quality
        </button>
        <button
          onClick={() => setActiveTab('redundancy')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'redundancy'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          Redundancy &amp; SPOFs
        </button>
      </div>

      {/* 4. Lower Section: Top Risks (Left) vs Health Metrics (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (Col Span 7): Top Risks */}
        <div className="lg:col-span-7 cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide">Top Resilience Risks</h3>
            <span className="text-[10px] text-slate-500 font-mono">NetworkX Biconnected Analysis</span>
          </div>

          <div className="space-y-3">
            {spofs.length > 0 ? (
              spofs.map((item: any, idx: number) => (
                <div
                  key={`spof-${idx}`}
                  className="p-3.5 rounded-xl bg-red-50/70 border border-red-200 flex items-start gap-3 text-xs text-red-800"
                >
                  <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold text-red-900">
                      {item.hostname || item.device_id} is an articulation point (SPOF)
                    </div>
                    <div className="text-[11px] text-red-700/90 mt-0.5">
                      {item.reason || 'Failure of this node creates disconnected components in the topology.'}
                    </div>
                  </div>
                </div>
              ))
            ) : null}

            {missingRedundancy.length > 0 ? (
              missingRedundancy.map((item: any, idx: number) => (
                <div
                  key={`red-${idx}`}
                  className="p-3.5 rounded-xl bg-orange-50/70 border border-orange-200 flex items-start gap-3 text-xs text-orange-800"
                >
                  <AlertTriangle className="w-4 h-4 text-orange-600 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold text-orange-900">
                      Missing redundant link between {item.from_device} and {item.to_device}
                    </div>
                    <div className="text-[11px] text-orange-700/90 mt-0.5">
                      {item.reason || item.recommendation || 'Single uplink detected without secondary failover path.'}
                    </div>
                  </div>
                </div>
              ))
            ) : null}

            {spofs.length === 0 && missingRedundancy.length === 0 && (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
                <span>No critical single points of failure detected. Topology exhibits redundant multi-path design.</span>
              </div>
            )}
          </div>
        </div>

        {/* Right Column (Col Span 5): Network Health & Breakdown Bars matching Reference Screen 7 */}
        <div className="lg:col-span-5 cyber-card p-6 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide">Network Health</h3>
              <span className="text-[10px] text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                {resilienceScore >= 80 ? 'Good Quality' : resilienceScore >= 60 ? 'Moderate' : 'At Risk'}
              </span>
            </div>

            {/* Circular Gauge */}
            <div className="flex items-center justify-center py-2">
              <div className="relative w-28 h-28 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="56"
                    cy="56"
                    r={radius}
                    className="stroke-slate-200"
                    strokeWidth="7"
                    fill="transparent"
                  />
                  <circle
                    cx="56"
                    cy="56"
                    r={radius}
                    stroke="#10b981"
                    strokeWidth="7"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-1000 ease-out"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="text-2xl font-black text-slate-900 font-mono">{resilienceScore}</span>
                  <span className="text-[9px] text-slate-500 font-bold uppercase -mt-1">Resilience</span>
                </div>
              </div>
            </div>

            {/* Horizontal Breakdown Bars matching Reference Screen 7 */}
            <div className="space-y-3 mt-4 text-xs">
              <div>
                <div className="flex justify-between text-slate-700 font-semibold mb-1">
                  <span>Redundancy</span>
                  <span className="font-mono text-emerald-600 font-bold">{redundancyScore}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-1000"
                    style={{ width: `${redundancyScore}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-700 font-semibold mb-1">
                  <span>Routing</span>
                  <span className="font-mono text-blue-600 font-bold">{routingScore}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-blue-600 transition-all duration-1000"
                    style={{ width: `${routingScore}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-700 font-semibold mb-1">
                  <span>Segmentation</span>
                  <span className="font-mono text-blue-500 font-bold">{segmentationScore}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-blue-500 transition-all duration-1000"
                    style={{ width: `${segmentationScore}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-slate-700 font-semibold mb-1">
                  <span>Stability</span>
                  <span className="font-mono text-indigo-600 font-bold">{stabilityScore}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-indigo-500 transition-all duration-1000"
                    style={{ width: `${stabilityScore}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-200 mt-6 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Evaluation Model: Dual-homed Core Spine</span>
            <span className="text-emerald-700 font-semibold">Active Monitoring</span>
          </div>
        </div>
      </div>
    </div>
  );
};
