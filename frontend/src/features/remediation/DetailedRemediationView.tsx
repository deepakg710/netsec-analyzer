import React, { useState } from 'react';
import { Finding } from '../../types';
import {
  CheckCircle2,
  Copy,
  Check,
  AlertTriangle,
  ArrowLeft,
  FileCode2,
  Info,
  ShieldCheck,
  Terminal,
  UserCheck,
  Briefcase,
  AlertCircle,
  Server,
  Layers,
  ChevronRight
} from 'lucide-react';

interface DetailedRemediationViewProps {
  finding: Finding | null;
  onBack: () => void;
  isProfessionalMode: boolean;
  onToggleMode: (isPro: boolean) => void;
  onMarkResolved?: (findingId: string) => void;
}

export const DetailedRemediationView: React.FC<DetailedRemediationViewProps> = ({
  finding,
  onBack,
  isProfessionalMode,
  onToggleMode,
  onMarkResolved,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'remediation' | 'validation'>('overview');
  const [copied, setCopied] = useState(false);
  const [isResolved, setIsResolved] = useState(finding?.is_resolved ?? false);

  if (!finding) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50">
        <h3 className="text-sm font-bold text-slate-700">No finding selected</h3>
        <button
          onClick={onBack}
          className="mt-3 px-4 py-2 rounded-lg bg-blue-600 text-white text-xs font-semibold hover:bg-blue-700"
        >
          Return to Findings Center
        </button>
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(finding.suggested_correction);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleResolveClick = () => {
    setIsResolved(true);
    if (onMarkResolved) {
      onMarkResolved(finding.id);
    }
  };

  const badgeColor =
    finding.severity === 'CRITICAL'
      ? 'bg-red-50 text-red-700 border border-red-200'
      : finding.severity === 'HIGH'
      ? 'bg-orange-50 text-orange-700 border border-orange-200'
      : finding.severity === 'MEDIUM'
      ? 'bg-amber-50 text-amber-800 border border-amber-200'
      : 'bg-blue-50 text-blue-700 border border-blue-200';

  const firstEvidence = finding.evidence && finding.evidence.length > 0 ? finding.evidence[0] : null;
  const evidenceLine = firstEvidence?.line_number ?? finding.line_number ?? 42;
  const evidenceFile = firstEvidence?.source_file ?? `${finding.device_id || 'Device'}_running-config.txt`;
  const evidenceSnippet = firstEvidence?.snippet ?? `line vty 0 4\n transport input telnet\n login\n password 7 0822455D0A16`;
  const verificationSteps =
    finding.verification_commands && finding.verification_commands.length > 0
      ? finding.verification_commands.join('\n')
      : finding.validation_plan && finding.validation_plan.length > 0
      ? finding.validation_plan.join('\n')
      : `1. show running-config | section vty\n2. ssh -v admin@${finding.device_id || '10.0.0.1'}\n3. telnet ${finding.device_id || '10.0.0.1'} (connection refused)`;

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Breadcrumb & Top Bar matching Reference Screen 6 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <button
            onClick={onBack}
            className="hover:text-blue-600 font-semibold transition-colors flex items-center gap-1"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Findings</span>
          </button>
          <span>/</span>
          <span className="font-mono text-blue-700 font-bold">{finding.rule_id}</span>
        </div>

        {/* In-View Explanation Depth Toggle */}
        <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-xl border border-slate-200">
          <button
            onClick={() => onToggleMode(false)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
              !isProfessionalMode
                ? 'bg-white text-blue-700 border border-slate-300 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <UserCheck className="w-3.5 h-3.5" />
            Beginner Mode
          </button>
          <button
            onClick={() => onToggleMode(true)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
              isProfessionalMode
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Briefcase className="w-3.5 h-3.5" />
            Professional Mode
          </button>
        </div>
      </div>

      {/* 2. Title & Status Banner matching Reference Screen 6 */}
      <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <span className={`text-xs font-extrabold px-2.5 py-0.5 rounded uppercase tracking-wider ${badgeColor}`}>
                {finding.severity}
              </span>
              <span className="text-xs font-mono font-bold text-blue-700">{finding.rule_id}</span>
              <span className="text-slate-500 text-xs">• {finding.category}</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 tracking-wide">{finding.title}</h2>
            <p className="text-xs text-slate-600 max-w-3xl">
              {isProfessionalMode
                ? `Observed on device ${finding.device_id || 'Global'} interface ${finding.interface_id || 'system lines'}. Configuration violates standard hardening baseline.`
                : 'This configuration weakness could expose your network equipment to unauthorized access or packet interception.'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            {isResolved ? (
              <span className="px-3.5 py-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>Resolved</span>
              </span>
            ) : (
              <span className="px-3.5 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-700 text-xs font-bold flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-blue-600" />
                <span>Open Issue</span>
              </span>
            )}
          </div>
        </div>

        {/* 3. Four Tabs matching Reference Screen 6 */}
        <div className="flex items-center gap-2 border-t border-slate-200 mt-5 pt-4">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'overview'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'evidence'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            Evidence &amp; Source
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'remediation'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            Remediation
          </button>
          <button
            onClick={() => setActiveTab('validation')}
            className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${
              activeTab === 'validation'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            Validation &amp; Tests
          </button>
        </div>
      </div>

      {/* 4. Two-Column Layout matching Reference Screen 6 */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (Col Span 6): What is wrong, Why it matters, Evidence */}
        <div className="lg:col-span-6 space-y-6">
          {/* What is wrong? */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-2">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-blue-600" />
              What is wrong?
            </h3>
            <p className="text-xs text-slate-700 leading-relaxed">
              {isProfessionalMode
                ? finding.what_is_wrong_professional
                : finding.what_is_wrong_beginner}
            </p>
          </div>

          {/* Why it matters? */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-2">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <Info className="w-4 h-4 text-amber-600" />
              Why it matters?
            </h3>
            <p className="text-xs text-slate-700 leading-relaxed">
              {isProfessionalMode
                ? finding.why_it_matters_professional
                : finding.why_it_matters_beginner}
            </p>
          </div>

          {/* Evidence Snippet */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-blue-600" />
                Configuration Evidence
              </h3>
              <div className="text-[11px] font-mono text-slate-500">
                Line:{' '}
                <span className="text-blue-700 font-bold">
                  {evidenceLine}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 font-mono text-xs">
              <div className="text-[10px] text-slate-400 border-b border-slate-800 pb-1.5 mb-2 flex items-center justify-between">
                <span>File: {evidenceFile}</span>
                <span className="text-blue-400">Device: {finding.device_id || 'R1'}</span>
              </div>
              <pre className="text-red-400 leading-relaxed overflow-x-auto">
                {evidenceSnippet}
              </pre>
            </div>
          </div>
        </div>

        {/* Right Column (Col Span 6): Recommended Fix, Potential Side Effects, Verification */}
        <div className="lg:col-span-6 space-y-6">
          {/* Recommended Fix */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-600" />
                Recommended Fix
              </h3>
              <button
                onClick={handleCopy}
                className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 text-[11px] font-bold flex items-center gap-1.5 transition-all shadow-xs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <pre className="bg-slate-900 p-3.5 rounded-xl border border-slate-800 font-mono text-xs text-emerald-400 leading-relaxed overflow-x-auto">
              {finding.suggested_correction}
            </pre>
          </div>

          {/* Potential Side Effects */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-2.5">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-600" />
              Potential Side Effects
            </h3>
            <div className="space-y-1.5 text-xs text-slate-700">
              <div className="flex items-start gap-2">
                <span className="text-amber-600 font-bold">•</span>
                <span>{finding.potential_side_effects}</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-amber-600 font-bold">•</span>
                <span>Requires active SSH client and configured local or TACACS+ credentials.</span>
              </div>
            </div>
          </div>

          {/* Verification Steps */}
          <div className="cyber-card p-6 bg-white border border-slate-200 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-blue-600" />
              Verification Steps
            </h3>
            <div className="p-3 bg-slate-900 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 whitespace-pre-line leading-relaxed">
              {verificationSteps}
            </div>
          </div>

          {/* Mark as Resolved Button */}
          <div>
            <button
              onClick={handleResolveClick}
              disabled={isResolved}
              className={`w-full py-3 px-4 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-sm ${
                isResolved
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 cursor-default'
                  : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-500/20'
              }`}
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>{isResolved ? 'Issue Marked as Resolved' : 'Mark as Resolved'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
