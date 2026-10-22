import React, { useState } from 'react';
import { Project, AnalysisRun } from '../../types';
import { apiClient } from '../../api/client';
import {
  FileText,
  Download,
  CheckCircle,
  Eye,
  Shield,
  Layers,
  Network,
  Printer,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Loader2,
  FileCode2,
  Lock,
  Server,
  Upload
} from 'lucide-react';

interface ReportGenerationViewProps {
  currentProject: Project | null;
  currentRun: AnalysisRun | null;
  onOpenUploadConfigs?: () => void;
}

export const ReportGenerationView: React.FC<ReportGenerationViewProps> = ({
  currentProject,
  currentRun,
  onOpenUploadConfigs,
}) => {

  if (!currentRun) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50 text-slate-900">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600 shadow-sm">
          <FileText className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Analysis Report Available</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Upload Cisco configurations and run an analysis to generate audit-ready Executive, Technical, and Remediation reports in HTML, PDF, or JSON format.
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

  const [format, setFormat] = useState<'html' | 'pdf' | 'json'>('html');
  const [includeSections, setIncludeSections] = useState({
    executiveSummary: true,
    findingsRemediation: true,
    topologyDiagram: true,
    riskScoreMetrics: true,
    beforeAfterComparison: true,
  });
  const [isGenerating, setIsGenerating] = useState(false);

  const toggleSection = (key: keyof typeof includeSections) => {
    setIncludeSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleGenerate = () => {
    if (!currentRun?.id) return;
    setIsGenerating(true);
    const url = apiClient.getReportDownloadUrl(currentRun.id, format);

    if (format === 'html') {
      window.open(url, '_blank');
    } else {
      const link = document.createElement('a');
      link.href = url;
      link.download = `NetSec_Assessment_${currentProject?.name || 'Report'}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
    setTimeout(() => setIsGenerating(false), 900);
  };

  const score = currentRun?.overall_score || 78;
  const sev = currentRun?.severity_counts || { CRITICAL: 3, HIGH: 7, MEDIUM: 12, LOW: 5 };
  const projectName = currentProject?.name || 'Enterprise_Campus';
  const genDate = currentRun?.timestamp ? currentRun.timestamp.slice(0, 16).replace('T', ' ') : 'Apr 24, 2025 14:32';

  // SVG Gauge calculations
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header matching Reference Screen 9 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <FileText className="w-6 h-6 text-blue-600" />
            Generate Security Report
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Export audit-ready pre-deployment assessments in interactive HTML, executive ReportLab PDF, or machine-readable JSON.
          </p>
        </div>
      </div>

      {/* 2. Main Two-Column Grid: Form (Left) vs Document Preview (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column (Col Span 6): Options Form matching Reference Screen 9 */}
        <div className="lg:col-span-6 cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900 tracking-wide uppercase">Report Configuration</h3>
            <p className="text-xs text-slate-500 mt-0.5">Customize output format and included sections</p>
          </div>

          {/* Format Radio Selection matching Reference 9 */}
          <div className="space-y-2.5">
            <label className="text-xs font-bold text-slate-600 block uppercase tracking-wider">Select Report Type</label>
            <div className="space-y-2.5">
              {/* HTML */}
              <label
                onClick={() => setFormat('html')}
                className={`flex items-center gap-3.5 p-3 rounded-xl border cursor-pointer transition-all ${
                  format === 'html'
                    ? 'bg-blue-50/80 border-blue-400 shadow-xs'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <input
                  type="radio"
                  name="format"
                  checked={format === 'html'}
                  onChange={() => setFormat('html')}
                  className="text-blue-600 focus:ring-0"
                />
                <div className="text-xs">
                  <div className="font-bold text-slate-900 flex items-center gap-2">
                    <span>HTML (Interactive)</span>
                    <span className="text-[10px] px-2 py-0.2 rounded bg-blue-100 text-blue-700 font-semibold border border-blue-200">
                      Recommended
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Interactive standalone browser report with live diagrams and printable CSS styling.
                  </p>
                </div>
              </label>

              {/* PDF */}
              <label
                onClick={() => setFormat('pdf')}
                className={`flex items-center gap-3.5 p-3 rounded-xl border cursor-pointer transition-all ${
                  format === 'pdf'
                    ? 'bg-blue-50/80 border-blue-400 shadow-xs'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <input
                  type="radio"
                  name="format"
                  checked={format === 'pdf'}
                  onChange={() => setFormat('pdf')}
                  className="text-blue-600 focus:ring-0"
                />
                <div className="text-xs">
                  <div className="font-bold text-slate-900">PDF (Printable)</div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Formal executive audit report compiled locally using ReportLab.
                  </p>
                </div>
              </label>

              {/* JSON */}
              <label
                onClick={() => setFormat('json')}
                className={`flex items-center gap-3.5 p-3 rounded-xl border cursor-pointer transition-all ${
                  format === 'json'
                    ? 'bg-blue-50/80 border-blue-400 shadow-xs'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <input
                  type="radio"
                  name="format"
                  checked={format === 'json'}
                  onChange={() => setFormat('json')}
                  className="text-blue-600 focus:ring-0"
                />
                <div className="text-xs">
                  <div className="font-bold text-slate-900">JSON (Machine Readable)</div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Structured canonical data payload for CI/CD pipelines and external tooling.
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Report Options Checkboxes matching Reference Screen 9 */}
          <div className="space-y-2.5">
            <label className="text-xs font-bold text-slate-600 block uppercase tracking-wider">Report Options</label>
            <div className="space-y-2 text-xs text-slate-700">
              <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSections.executiveSummary}
                  onChange={() => toggleSection('executiveSummary')}
                  className="rounded border-slate-300 bg-white text-blue-600 focus:ring-0"
                />
                <span className="font-medium text-slate-800">Executive Summary &amp; Scorecard</span>
              </label>

              <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSections.findingsRemediation}
                  onChange={() => toggleSection('findingsRemediation')}
                  className="rounded border-slate-300 bg-white text-blue-600 focus:ring-0"
                />
                <span className="font-medium text-slate-800">Detailed Findings &amp; Step-by-Step Remediation</span>
              </label>

              <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSections.topologyDiagram}
                  onChange={() => toggleSection('topologyDiagram')}
                  className="rounded border-slate-300 bg-white text-blue-600 focus:ring-0"
                />
                <span className="font-medium text-slate-800">Topology Architecture &amp; VLAN Boundaries</span>
              </label>

              <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSections.riskScoreMetrics}
                  onChange={() => toggleSection('riskScoreMetrics')}
                  className="rounded border-slate-300 bg-white text-blue-600 focus:ring-0"
                />
                <span className="font-medium text-slate-800">Attack-Path Traversal &amp; Resilience Metrics</span>
              </label>

              <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSections.beforeAfterComparison}
                  onChange={() => toggleSection('beforeAfterComparison')}
                  className="rounded border-slate-300 bg-white text-blue-600 focus:ring-0"
                />
                <span className="font-medium text-slate-800">Before &amp; After Delta Comparison</span>
              </label>
            </div>
          </div>

          {/* Generate Button */}
          <button
            onClick={handleGenerate}
            disabled={isGenerating || !currentRun}
            className="w-full py-3.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-bold text-xs shadow-sm flex items-center justify-center gap-2 transition-all"
          >
            {isGenerating ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Compiling Assessment Report...</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                <span>Generate &amp; Download Report ({format.toUpperCase()})</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column (Col Span 6): Report Preview Card matching Reference Screen 9 */}
        <div className="lg:col-span-6 space-y-4">
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-md relative overflow-hidden flex flex-col justify-between min-h-[500px]">
            {/* Top Preview Header */}
            <div>
              <div className="flex items-center justify-between border-b border-slate-200 pb-4 mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 p-[1px] flex items-center justify-center shadow-xs">
                    <div className="w-full h-full bg-blue-50 rounded-xl flex items-center justify-center">
                      <Shield className="w-5 h-5 text-blue-600" />
                    </div>
                  </div>
                  <div>
                    <h4 className="text-sm font-extrabold text-slate-900 tracking-wide">NetSec Analyzer</h4>
                    <p className="text-[10px] text-blue-600 font-mono font-semibold">Network Security Assessment Report</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className="inline-block px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-blue-50 border border-blue-200 text-blue-700">
                    Official Audit
                  </span>
                </div>
              </div>

              {/* Meta */}
              <div className="grid grid-cols-2 gap-3 bg-slate-50 p-3 rounded-xl border border-slate-200 text-[11px] mb-4">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Project</span>
                  <span className="font-mono font-bold text-slate-800">{projectName}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Generated</span>
                  <span className="font-mono text-slate-700">{genDate}</span>
                </div>
              </div>

              {/* Score & Topology Thumbnail Mockup */}
              <div className="grid grid-cols-12 gap-4 items-center bg-slate-50 p-4 rounded-xl border border-slate-200 mb-4">
                {/* Score */}
                <div className="col-span-5 flex flex-col items-center justify-center text-center border-r border-slate-200 pr-2">
                  <div className="relative w-20 h-20 flex items-center justify-center">
                    <svg className="w-full h-full transform -rotate-90">
                      <circle
                        cx="40"
                        cy="40"
                        r={radius}
                        className="stroke-slate-200"
                        strokeWidth="5"
                        fill="transparent"
                      />
                      <circle
                        cx="40"
                        cy="40"
                        r={radius}
                        stroke="#0284c7"
                        strokeWidth="5"
                        strokeDasharray={circumference}
                        strokeDashoffset={strokeDashoffset}
                        strokeLinecap="round"
                        fill="transparent"
                      />
                    </svg>
                    <div className="absolute flex flex-col items-center justify-center">
                      <span className="text-lg font-black text-slate-900 font-mono">{score}</span>
                      <span className="text-[8px] text-slate-400 font-bold uppercase -mt-1">/100</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-bold text-blue-700 mt-1 uppercase">Security Score</span>
                </div>

                {/* Topology Schematic Thumbnail */}
                <div className="col-span-7 flex flex-col items-center justify-center text-center p-2">
                  <div className="w-full h-20 rounded-lg bg-white border border-slate-200 flex items-center justify-center relative overflow-hidden shadow-xs">
                    {/* Abstract Mini Topology Nodes */}
                    <div className="flex items-center gap-3">
                      <div className="w-5 h-5 rounded-md bg-blue-50 border border-blue-400 flex items-center justify-center">
                        <Network className="w-3 h-3 text-blue-600" />
                      </div>
                      <div className="w-6 h-0.5 bg-blue-400" />
                      <div className="w-5 h-5 rounded-md bg-indigo-50 border border-indigo-400 flex items-center justify-center">
                        <Shield className="w-3 h-3 text-indigo-600" />
                      </div>
                      <div className="w-6 h-0.5 bg-emerald-400" />
                      <div className="w-5 h-5 rounded-md bg-emerald-50 border border-emerald-400 flex items-center justify-center">
                        <Server className="w-3 h-3 text-emerald-600" />
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500 mt-1">Multi-Tier Architecture Diagram</span>
                </div>
              </div>

              {/* Findings Summary Mini Table */}
              <div>
                <div className="text-[10px] uppercase font-bold text-slate-500 mb-2">Findings Summary</div>
                <div className="grid grid-cols-4 gap-2 text-center text-xs">
                  <div className="p-2 rounded-lg bg-red-50 border border-red-200">
                    <div className="text-red-700 font-bold font-mono text-sm">{sev.CRITICAL || 0}</div>
                    <div className="text-[9px] text-slate-500 uppercase font-semibold">Critical</div>
                  </div>
                  <div className="p-2 rounded-lg bg-orange-50 border border-orange-200">
                    <div className="text-orange-700 font-bold font-mono text-sm">{sev.HIGH || 0}</div>
                    <div className="text-[9px] text-slate-500 uppercase font-semibold">High</div>
                  </div>
                  <div className="p-2 rounded-lg bg-amber-50 border border-amber-200">
                    <div className="text-amber-800 font-bold font-mono text-sm">{sev.MEDIUM || 0}</div>
                    <div className="text-[9px] text-slate-500 uppercase font-semibold">Med</div>
                  </div>
                  <div className="p-2 rounded-lg bg-blue-50 border border-blue-200">
                    <div className="text-blue-700 font-bold font-mono text-sm">{sev.LOW || 0}</div>
                    <div className="text-[9px] text-slate-500 uppercase font-semibold">Low</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Bottom Confidential Badge */}
            <div className="pt-4 border-t border-slate-200 flex items-center justify-between text-[10px] text-slate-500">
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-slate-400" />
                Confidential • For Internal Use Only
              </span>
              <span>Last generated: {genDate}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
