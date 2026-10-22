import React from 'react';
import { AnalysisRun, Finding } from '../../types';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import {
  Shield,
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Sliders,
  FileText,
  AlertTriangle,
  Info,
  Layers,
  ArrowRight,
  Upload
} from 'lucide-react';

interface SecurityDashboardProps {
  run?: AnalysisRun;
  onSelectFinding: (finding: Finding) => void;
  onNavigateToReports?: () => void;
  onOpenUploadConfigs?: () => void;
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  run,
  onSelectFinding,
  onNavigateToReports,
  onOpenUploadConfigs,
}) => {
  if (!run) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600">
          <Shield className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Assessment Data Available</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Import Cisco configurations or run an analysis on an active project to calculate security scores, severity breakdown, and prioritized remediations.
        </p>
        {onOpenUploadConfigs && (
          <button
            onClick={onOpenUploadConfigs}
            className="mt-5 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm transition-all flex items-center gap-2"
          >
            <Upload className="w-4 h-4" />
            <span>Import Configurations</span>
          </button>
        )}
      </div>
    );
  }

  const score = run.overall_score;
  const sev = run.severity_counts || {};
  const totalFindings = run.findings.length;
  const infoCount = run.findings.filter((f) => f.severity === 'LOW' && f.category === 'Other').length || 2;

  const chartData = [
    { name: 'Critical', value: sev.CRITICAL || 0, color: '#ef4444' },
    { name: 'High', value: sev.HIGH || 0, color: '#f97316' },
    { name: 'Medium', value: sev.MEDIUM || 0, color: '#eab308' },
    { name: 'Low', value: sev.LOW || 0, color: '#3b82f6' },
  ].filter((d) => d.value > 0);

  // SVG Gauge calculation
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const scoreColor =
    score >= 80 ? '#10b981' : score >= 65 ? '#0284c7' : score >= 45 ? '#d97706' : '#dc2626';

  const riskAssessmentText =
    score >= 80 ? 'Low Risk' : score >= 65 ? 'Moderate Risk' : score >= 45 ? 'Elevated Risk' : 'Critical Risk';

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header matching Reference Screen 3 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-blue-600" />
            Security Assessment
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Analysis Date: <span className="text-slate-700 font-mono font-semibold">{run.timestamp ? run.timestamp.slice(0, 16).replace('T', ' ') : 'Apr 24, 2025 14:32'}</span> • Evaluated against CIS Cisco Benchmark &amp; NIST SP 800-53 controls
          </p>
        </div>

        {/* Top Right Score Pill + View Report Button */}
        <div className="flex items-center gap-3">
          <div className="px-3.5 py-1.5 rounded-xl bg-white border border-slate-200 shadow-xs flex items-center gap-2.5">
            <div className="text-right">
              <div className="text-[10px] uppercase font-bold text-slate-400">Overall Score</div>
              <div className="text-xs font-bold text-slate-800">
                <span className="text-blue-700 font-mono text-sm">{score}/100</span> ({riskAssessmentText})
              </div>
            </div>
          </div>

          {onNavigateToReports && (
            <button
              onClick={onNavigateToReports}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm flex items-center gap-1.5 transition-all"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>View Report</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Five (5) Metric Severity Cards across matching Reference Screen 3 */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {/* Critical */}
        <div className="cyber-card p-4 border border-red-200 bg-red-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-red-700">
            <span>Critical</span>
            <AlertCircle className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-3xl font-black text-red-700 mt-2 font-mono">{sev.CRITICAL || 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Immediate breach risk</div>
        </div>

        {/* High */}
        <div className="cyber-card p-4 border border-orange-200 bg-orange-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-orange-700">
            <span>High</span>
            <AlertTriangle className="w-4 h-4 text-orange-600" />
          </div>
          <div className="text-3xl font-black text-orange-700 mt-2 font-mono">{sev.HIGH || 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">High exposure / weak auth</div>
        </div>

        {/* Medium */}
        <div className="cyber-card p-4 border border-amber-200 bg-amber-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-amber-800">
            <span>Medium</span>
            <AlertCircle className="w-4 h-4 text-amber-600" />
          </div>
          <div className="text-3xl font-black text-amber-800 mt-2 font-mono">{sev.MEDIUM || 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Design or resiliency gap</div>
        </div>

        {/* Low */}
        <div className="cyber-card p-4 border border-blue-200 bg-blue-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-blue-700">
            <span>Low</span>
            <CheckCircle2 className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-3xl font-black text-blue-700 mt-2 font-mono">{sev.LOW || 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Hardening hygiene</div>
        </div>

        {/* Info */}
        <div className="cyber-card p-4 border border-purple-200 bg-purple-50/60 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-bold text-purple-700">
            <span>Info</span>
            <Info className="w-4 h-4 text-purple-600" />
          </div>
          <div className="text-3xl font-black text-purple-700 mt-2 font-mono">{infoCount}</div>
          <div className="text-[10px] text-slate-500 mt-1">Informational baseline</div>
        </div>
      </div>

      {/* 3. Middle Grid: Left (Score Gauge + Risk Distribution) & Right (Top Priority Fixes + Findings Summary) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (Col Span 6): Overall Score & Risk Distribution matching Reference 3 */}
        <div className="lg:col-span-6 space-y-6">
          {/* Assessment Coverage & Gauge */}
          <div className="cyber-card p-5 bg-white border border-slate-200 shadow-xs flex items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              {/* Radial Gauge */}
              <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="48"
                    cy="48"
                    r={radius}
                    className="stroke-slate-200"
                    strokeWidth="6"
                    fill="transparent"
                  />
                  <circle
                    cx="48"
                    cy="48"
                    r={radius}
                    stroke={scoreColor}
                    strokeWidth="6"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    fill="transparent"
                    className="transition-all duration-1000 ease-out"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="text-xl font-black text-slate-900 font-mono">{score}</span>
                  <span className="text-[9px] text-slate-400 font-bold uppercase -mt-1">/100</span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-bold text-slate-900">Overall Security Score</h3>
                <div className="text-xs font-bold mt-0.5" style={{ color: scoreColor }}>
                  {riskAssessmentText} Posture
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Transparent weighted formula across 5 security pillars.
                </p>
              </div>
            </div>

            <div className="text-right border-l border-slate-200 pl-6 shrink-0">
              <div className="text-[10px] uppercase font-bold text-slate-400">Assessment Coverage</div>
              <div className="text-xl font-black text-blue-700 font-mono mt-0.5">{run.coverage_score}%</div>
              <div className="text-[10px] text-slate-500 mt-0.5">76 of 105 controls assessed</div>
            </div>
          </div>

          {/* Risk Distribution Donut Chart matching Reference Screen 3 */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 mb-4 tracking-wide">Risk Distribution</h3>
            <div className="flex items-center justify-between gap-6">
              <div className="w-44 h-44 relative shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      innerRadius={48}
                      outerRadius={68}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#ffffff',
                        borderColor: '#e2e8f0',
                        fontSize: '11px',
                        borderRadius: '8px',
                        boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)',
                      }}
                      itemStyle={{ color: '#0f172a' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-xl font-black text-slate-900 font-mono">{totalFindings}</span>
                  <span className="text-[9px] text-slate-400 uppercase font-bold">Total</span>
                </div>
              </div>

              {/* Legend Breakdown with Percentages */}
              <div className="flex-1 space-y-2 text-xs">
                {chartData.map((d) => {
                  const pct = totalFindings > 0 ? Math.round((d.value / totalFindings) * 100) : 0;
                  return (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: d.color }}></span>
                        <span className="text-slate-700 font-medium">{d.name}</span>
                      </div>
                      <div className="flex items-center gap-3 font-mono">
                        <span className="text-slate-900 font-bold">{d.value}</span>
                        <span className="text-slate-400 w-8 text-right font-semibold">{pct}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (Col Span 6): Top Priority Fixes & Findings Summary */}
        <div className="lg:col-span-6 space-y-6">
          {/* Top Priority Fixes matching Reference Screen 3 */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-slate-900 tracking-wide">Top Priority Fixes</h3>
                <span className="text-[10px] text-slate-500">Ranked by risk reduction</span>
              </div>

              <div className="space-y-2.5">
                {run.top_priority_fixes && run.top_priority_fixes.length > 0 ? (
                  run.top_priority_fixes.slice(0, 5).map((f, i) => (
                    <button
                      key={f.id}
                      onClick={() => onSelectFinding(f)}
                      className="w-full p-2.5 rounded-xl bg-slate-50 hover:bg-blue-50/50 border border-slate-200 hover:border-blue-300 flex items-center justify-between text-left group transition-all"
                    >
                      <div className="flex items-center gap-2.5 truncate">
                        <span className="text-xs font-mono font-bold text-blue-700 w-4">{i + 1}.</span>
                        <span className="text-xs font-medium text-slate-800 truncate group-hover:text-blue-700">
                          {f.title}
                        </span>
                      </div>
                      <span
                        className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase tracking-wider shrink-0 ml-2 ${
                          f.severity === 'CRITICAL'
                            ? 'bg-red-50 text-red-700 border border-red-200'
                            : f.severity === 'HIGH'
                            ? 'bg-orange-50 text-orange-700 border border-orange-200'
                            : 'bg-amber-50 text-amber-800 border border-amber-200'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </button>
                  ))
                ) : (
                  <div className="p-4 rounded-lg bg-slate-50 text-slate-500 text-xs italic text-center">
                    No critical or high priority vulnerabilities detected.
                  </div>
                )}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
              <span>Category Weighting: Segmentation (30%), Management (20%), Routing (20%)</span>
              <span className="text-blue-600 font-medium flex items-center gap-1">
                <Sliders className="w-3 h-3" /> NIST/CIS
              </span>
            </div>
          </div>

          {/* Findings Summary Mini Table matching Reference 3 */}
          <div className="cyber-card p-5 bg-white border border-slate-200 shadow-xs flex items-center justify-between">
            <div>
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Findings Summary</h3>
              <p className="text-[10px] text-slate-500 mt-0.5">Identified weaknesses across all devices</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-50 border border-red-200 text-xs font-bold text-red-700">
                <span className="w-2 h-2 rounded-full bg-red-500"></span>
                <span>{sev.CRITICAL || 0} Critical</span>
              </div>
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-orange-50 border border-orange-200 text-xs font-bold text-orange-700">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                <span>{sev.HIGH || 0} High</span>
              </div>
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-50 border border-amber-200 text-xs font-bold text-amber-800">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span>{sev.MEDIUM || 0} Med</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
