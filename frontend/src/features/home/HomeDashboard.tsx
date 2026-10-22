import React, { useState, useRef } from 'react';
import { Project, AnalysisRun } from '../../types';
import {
  Shield,
  Upload,
  FileCode2,
  FolderPlus,
  ArrowRight,
  ShieldCheck,
  AlertCircle,
  Zap,
  Server,
  Network,
  CheckCircle2,
  Clock,
  Layers,
  FileText,
  AlertTriangle,
  Loader2
} from 'lucide-react';
import { apiClient } from '../../api/client';

interface HomeDashboardProps {
  currentProject: Project | null;
  currentRun: AnalysisRun | null;
  projects: Project[];
  onSelectProject: (proj: Project) => void;
  onOpenUploadPkt: (file?: File, report?: any) => void;
  onOpenUploadConfigs: () => void;
  onCreateNewProject: () => void;
  onLoadSample: (type: 'vulnerable' | 'hardened' | 'large_enterprise' | '3_network') => void;
  onNavigate: (screen: any) => void;
  onFileUploadSuccess?: (projectId: string) => Promise<void>;
}

export const HomeDashboard: React.FC<HomeDashboardProps> = ({
  currentProject,
  currentRun,
  projects,
  onSelectProject,
  onOpenUploadPkt,
  onOpenUploadConfigs,
  onCreateNewProject,
  onLoadSample,
  onNavigate,
  onFileUploadSuccess,
}) => {
  // Upload status and stepper state for the bottom "Easy File Upload Method"
  const [uploadStep, setUploadStep] = useState<number>(0); // 0 = idle, 1 = validation, 2 = parsing, 3 = analysis, 4 = results
  const [uploadedFileName, setUploadedFileName] = useState<string>('');
  const [uploadedFileSize, setUploadedFileSize] = useState<string>('');
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Compute metrics from current active run or projects
  const hasRun = Boolean(currentRun);
  const score = currentRun?.overall_score ?? (projects.length > 0 && projects[0].last_score ? projects[0].last_score : null);
  const sev = currentRun?.severity_counts ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const devicesCount = currentRun?.devices_count ?? 0;
  const interfacesCount = currentRun?.interfaces_count ?? 0;
  const vlansCount = currentRun?.topology?.vlans?.length ?? 0;
  const findingsCount = currentRun?.findings?.length ?? 0;
  const coveragePercent = currentRun?.coverage_score ?? 0;

  // SVG Gauge calculations
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = score !== null ? circumference - (score / 100) * circumference : circumference;
  const scoreColor =
    score === null
      ? '#cbd5e1'
      : score >= 80
      ? '#10b981'
      : score >= 65
      ? '#06b6d4'
      : score >= 45
      ? '#f59e0b'
      : '#ef4444';

  const handleFileDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processSelectedFile(e.target.files[0]);
    }
  };

  const processSelectedFile = async (file: File) => {
    setIsUploading(true);
    setUploadError(null);
    setUploadedFileName(file.name);
    setUploadedFileSize(`${(file.size / (1024 * 1024)).toFixed(1)} MB`);
    
    // Step 1: Validation
    setUploadStep(1);
    await new Promise((r) => setTimeout(r, 400));

    try {
      let targetProjectId = currentProject?.id || '';

      // Step 2: Parsing
      setUploadStep(2);
      if (file.name.toLowerCase().endsWith('.pkt')) {
        const res = await apiClient.uploadPkt(targetProjectId, file);
        if (res.extracted_devices_count === 0 || res.status === 'Unsupported') {
          // Open the modal with pre-loaded file and full diagnostic report
          onOpenUploadPkt(file, res);
          setIsUploading(false);
          setUploadStep(0);
          return;
        }
        targetProjectId = res.project_id || targetProjectId;
      } else {
        const res = await apiClient.uploadConfigs(targetProjectId, [file]);
        targetProjectId = res.project_id || targetProjectId;
      }

      // Step 3: Analysis
      setUploadStep(3);
      await apiClient.runAnalysis(targetProjectId);

      // Step 4: Results
      setUploadStep(4);
      if (onFileUploadSuccess) {
        await onFileUploadSuccess(targetProjectId);
      }
    } catch (err: any) {
      console.error('Upload processing error:', err);
      setUploadError(err.message || 'Failed to process file');
      setUploadStep(0);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header matching Reference Screen 1 */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-blue-600" />
            Welcome to NetSec Analyzer
          </h1>
          <p className="text-sm font-semibold text-blue-600 mt-0.5">
            Analyze • Detect • Strengthen
          </p>
          <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
            Upload your network design or configuration files to identify security risks, attack paths and get actionable recommendations before deployment.
          </p>
        </div>

        {/* Quick Sample Networks */}
        <div className="flex items-center gap-2 bg-slate-100 p-1.5 rounded-xl border border-slate-200">
          <span className="text-[11px] font-bold text-slate-600 px-2 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            Samples:
          </span>
          <button
            onClick={() => onLoadSample('3_network')}
            className="px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 text-xs font-semibold transition-all shadow-xs flex items-center gap-1"
          >
            <Network className="w-3.5 h-3.5 text-indigo-600" />
            3 Networks (Packet Tracer)
          </button>
          <button
            onClick={() => onLoadSample('large_enterprise')}
            className="px-2.5 py-1 rounded-lg bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-700 text-xs font-semibold transition-all shadow-xs flex items-center gap-1"
          >
            <Network className="w-3.5 h-3.5 text-blue-600" />
            🏢 Big Network (6 Dev)
          </button>
          <button
            onClick={() => onLoadSample('vulnerable')}
            className="px-2 py-1 rounded-lg bg-red-50 hover:bg-red-100 border border-red-200 text-red-700 text-xs font-semibold transition-all"
          >
            Vulnerable
          </button>
          <button
            onClick={() => onLoadSample('hardened')}
            className="px-2 py-1 rounded-lg bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 text-emerald-700 text-xs font-semibold transition-all"
          >
            Hardened
          </button>
        </div>
      </div>

      {/* 2. Three Action Cards matching Reference Screen 1 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Upload Packet Tracer File */}
        <button
          onClick={() => onOpenUploadPkt()}
          className="cyber-card p-5 text-left hover:border-blue-400 hover:shadow-md transition-all group flex flex-col justify-between bg-white border border-slate-200"
        >
          <div>
            <div className="w-11 h-11 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
              <Upload className="w-5 h-5 text-blue-600" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
              Upload Packet Tracer File
            </h3>
            <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed">
              (.pkt) Inspect and validate Cisco Packet Tracer files. Evaluates encryption container and carves configuration streams.
            </p>
          </div>
          <div className="mt-4 flex items-center text-xs font-semibold text-blue-600 gap-1">
            <span>Inspect .pkt File</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Card 2: Import Configurations */}
        <button
          onClick={onOpenUploadConfigs}
          className="cyber-card p-5 text-left hover:border-blue-400 hover:shadow-md transition-all group flex flex-col justify-between bg-white border border-slate-200"
        >
          <div>
            <div className="w-11 h-11 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
              <FileCode2 className="w-5 h-5 text-indigo-600" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
              Import Configurations
            </h3>
            <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed">
              (routers &amp; switches) Upload Cisco IOS running-config exports or show command outputs with full line-numbered evidence provenance.
            </p>
          </div>
          <div className="mt-4 flex items-center text-xs font-semibold text-indigo-600 gap-1">
            <span>Import Router/Switch Configs</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Card 3: Create New Project */}
        <button
          onClick={onCreateNewProject}
          className="cyber-card p-5 text-left hover:border-emerald-400 hover:shadow-md transition-all group flex flex-col justify-between bg-white border border-slate-200"
        >
          <div>
            <div className="w-11 h-11 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform">
              <FolderPlus className="w-5 h-5 text-emerald-600" />
            </div>
            <h3 className="text-sm font-bold text-slate-900 group-hover:text-emerald-600 transition-colors">
              Create New Project
            </h3>
            <p className="text-[11px] text-slate-500 mt-1.5 leading-relaxed">
              Initialize a clean workspace for a new campus network, data center, or branch office design with independent versioning.
            </p>
          </div>
          <div className="mt-4 flex items-center text-xs font-semibold text-emerald-600 gap-1">
            <span>Start Fresh Project</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>
      </div>

      {/* 3. Middle Section: Recent Projects + Quick Stats + Security Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Recent Projects Table (Col span 5) matching Reference Screen 1 */}
        <div className="lg:col-span-5 cyber-card p-5 flex flex-col justify-between bg-white border border-slate-200 shadow-xs">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide">Recent Projects</h3>
              <span className="text-[11px] font-mono text-blue-700 font-semibold">{projects.length} Saved</span>
            </div>

            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="text-[10px] uppercase font-bold text-slate-500 border-b border-slate-200">
                    <th className="pb-2">Name</th>
                    <th className="pb-2">Last Analysis</th>
                    <th className="pb-2 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {projects.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="py-6 text-center text-slate-400">
                        <p className="text-xs font-medium">Clean State: 0 Projects in Database</p>
                        <p className="text-[10px] text-slate-500 mt-1">Import configurations or load a sample network above.</p>
                      </td>
                    </tr>
                  ) : (
                    projects.slice(0, 5).map((p) => {
                      const isSelected = currentProject?.id === p.id;
                      const hasScore = p.last_score !== undefined && p.last_score !== null;
                      return (
                        <tr
                          key={p.id}
                          onClick={() => onSelectProject(p)}
                          className={`cursor-pointer transition-colors ${
                            isSelected ? 'bg-blue-50/70' : 'hover:bg-slate-50'
                          }`}
                        >
                          <td className="py-2.5 font-medium text-slate-800">
                            <div className="truncate max-w-[130px] font-semibold">{p.name}</div>
                          </td>
                          <td className="py-2.5 text-slate-500 text-[11px] font-mono">
                            {p.created_at ? p.created_at.slice(0, 16).replace('T', ' ') : 'Just now'}
                          </td>
                          <td className="py-2.5 text-right">
                            {hasScore ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                                Completed
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
                                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse"></span>
                                In Progress
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
            <span>Local SQLite persistence</span>
            {projects.length > 0 && (
              <button
                onClick={() => onNavigate('projects')}
                className="text-blue-600 hover:text-blue-700 font-semibold transition-colors"
              >
                View all ({projects.length}) &rarr;
              </button>
            )}
          </div>
        </div>

        {/* Center: Quick Stats matching Reference Screen 1 Collage (Col span 3) */}
        <div className="lg:col-span-3 cyber-card p-5 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <div className="pb-3 border-b border-slate-200">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide">Quick Stats</h3>
              <p className="text-[10px] text-slate-500 mt-0.5">Active Network Inventory</p>
            </div>

            <div className="grid grid-cols-2 gap-3 mt-4">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-600">
                  <span className="text-[11px] font-semibold">Devices</span>
                  <Server className="w-3.5 h-3.5 text-blue-600" />
                </div>
                <div className="text-2xl font-black text-slate-900 mt-1">{devicesCount}</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-600">
                  <span className="text-[11px] font-semibold">Interfaces</span>
                  <Network className="w-3.5 h-3.5 text-indigo-600" />
                </div>
                <div className="text-2xl font-black text-slate-900 mt-1">{interfacesCount}</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-600">
                  <span className="text-[11px] font-semibold">VLANs</span>
                  <Layers className="w-3.5 h-3.5 text-purple-600" />
                </div>
                <div className="text-2xl font-black text-slate-900 mt-1">{vlansCount}</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-600">
                  <span className="text-[11px] font-semibold">Findings</span>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
                </div>
                <div className="text-2xl font-black text-slate-900 mt-1">{findingsCount}</div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 text-[10px] text-slate-600 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            <span>Deterministic graph reconstruction</span>
          </div>
        </div>

        {/* Right: Security Overview / Overall Score (Col span 4) matching Reference Screen 1 */}
        <div className="lg:col-span-4 cyber-card p-5 bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <h3 className="text-sm font-bold text-slate-900 tracking-wide">Security Overview</h3>
              <span className="text-[10px] text-slate-500 font-semibold">Coverage: {coveragePercent}%</span>
            </div>

            <div className="flex items-center gap-5 mt-4">
              {/* Radial Score Gauge */}
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
                  <span className="text-xl font-black text-slate-900">{score !== null ? score : '--'}</span>
                  <span className="text-[9px] text-slate-500 font-bold uppercase -mt-1">/100</span>
                </div>
              </div>

              {/* Severity Breakdown Badges matching Reference 1 */}
              <div className="space-y-1.5 flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-slate-700 font-medium">
                    <span className="w-2.5 h-2.5 rounded-sm bg-red-500"></span>
                    Critical
                  </span>
                  <span className="font-bold text-red-600 font-mono">{sev.CRITICAL || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-slate-700 font-medium">
                    <span className="w-2.5 h-2.5 rounded-sm bg-orange-500"></span>
                    High
                  </span>
                  <span className="font-bold text-orange-600 font-mono">{sev.HIGH || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-slate-700 font-medium">
                    <span className="w-2.5 h-2.5 rounded-sm bg-amber-500"></span>
                    Medium
                  </span>
                  <span className="font-bold text-amber-600 font-mono">{sev.MEDIUM || 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-slate-700 font-medium">
                    <span className="w-2.5 h-2.5 rounded-sm bg-blue-500"></span>
                    Low
                  </span>
                  <span className="font-bold text-blue-600 font-mono">{sev.LOW || 0}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 flex items-center justify-between">
            <span className="text-[11px] text-slate-500">CIS/NIST Hardening Baseline</span>
            {hasRun ? (
              <button
                onClick={() => onNavigate('security')}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <span>View Analysis</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                onClick={onOpenUploadConfigs}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <span>Upload to Analyze</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 4. Bottom Strip: "Easy File Upload Method" exact replica from Reference Image */}
      <div className="cyber-card p-5 bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-200 pb-2.5">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-900 tracking-wide uppercase">Easy File Upload Method</h4>
              <p className="text-[11px] text-slate-500">
                Upload Network Files: Drag and drop your Packet Tracer (.pkt) file or configuration exports
              </p>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 font-mono">
            Supported: <span className="text-blue-700 font-semibold">.pkt, .txt, .cfg, .ios, .conf</span> (Max 50MB)
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-center">
          {/* Dropzone Box */}
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
            className="lg:col-span-5 p-4 rounded-xl border border-dashed border-slate-300 hover:border-blue-500 bg-slate-50 cursor-pointer transition-all hover:bg-blue-50/40 flex items-center gap-3 group"
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileInputChange}
              accept=".pkt,.txt,.cfg,.ios,.conf"
              className="hidden"
            />
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center group-hover:scale-105 transition-transform shrink-0">
              <Upload className="w-4 h-4 text-blue-600" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-bold text-slate-800 group-hover:text-blue-600 transition-colors">
                Drag &amp; drop files here or <span className="text-blue-600 underline underline-offset-2">click to browse</span>
              </p>
              <p className="text-[10px] text-slate-500 mt-0.5 truncate">
                Cisco running-configs or Packet Tracer .pkt files
              </p>
            </div>
          </div>

          {/* Stepper with 4 milestones */}
          <div className="lg:col-span-4 flex items-center justify-between px-2 text-xs font-semibold">
            {/* Step 1 */}
            <div className="flex flex-col items-center gap-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                uploadStep >= 1 ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-200 text-slate-600'
              }`}>
                {uploadStep >= 1 ? <CheckCircle2 className="w-3.5 h-3.5" /> : '1'}
              </div>
              <span className={`text-[10px] font-semibold ${uploadStep >= 1 ? 'text-blue-700' : 'text-slate-500'}`}>Validation</span>
            </div>
            <div className={`flex-1 h-0.5 mx-1.5 ${uploadStep >= 2 ? 'bg-blue-600' : 'bg-slate-200'}`} />

            {/* Step 2 */}
            <div className="flex flex-col items-center gap-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                uploadStep >= 2 ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-200 text-slate-600'
              }`}>
                {uploadStep >= 2 ? <CheckCircle2 className="w-3.5 h-3.5" /> : '2'}
              </div>
              <span className={`text-[10px] font-semibold ${uploadStep >= 2 ? 'text-blue-700' : 'text-slate-500'}`}>Parsing</span>
            </div>
            <div className={`flex-1 h-0.5 mx-1.5 ${uploadStep >= 3 ? 'bg-blue-600' : 'bg-slate-200'}`} />

            {/* Step 3 */}
            <div className="flex flex-col items-center gap-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                uploadStep >= 3 ? 'bg-blue-600 text-white shadow-sm' : 'bg-slate-200 text-slate-600'
              }`}>
                {uploadStep >= 3 ? <CheckCircle2 className="w-3.5 h-3.5" /> : '3'}
              </div>
              <span className={`text-[10px] font-semibold ${uploadStep >= 3 ? 'text-blue-700' : 'text-slate-500'}`}>Analysis</span>
            </div>
            <div className={`flex-1 h-0.5 mx-1.5 ${uploadStep >= 4 ? 'bg-emerald-600' : 'bg-slate-200'}`} />

            {/* Step 4 */}
            <div className="flex flex-col items-center gap-1">
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold ${
                uploadStep >= 4 ? 'bg-emerald-600 text-white shadow-sm' : 'bg-slate-200 text-slate-600'
              }`}>
                {uploadStep >= 4 ? <CheckCircle2 className="w-3.5 h-3.5" /> : '4'}
              </div>
              <span className={`text-[10px] font-semibold ${uploadStep >= 4 ? 'text-emerald-700' : 'text-slate-500'}`}>Results</span>
            </div>
          </div>

          {/* Upload Status & View Analysis button */}
          <div className="lg:col-span-3 flex items-center justify-end gap-3">
            {uploadStep === 4 ? (
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-[11px] font-bold text-emerald-700 flex items-center gap-1 justify-end">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    File analyzed!
                  </div>
                  <div className="text-[10px] text-slate-500 truncate max-w-[140px] font-mono">
                    {uploadedFileName} ({uploadedFileSize})
                  </div>
                </div>
                <button
                  onClick={() => onNavigate('topology')}
                  className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm flex items-center gap-1.5 transition-all"
                >
                  <span>View Analysis</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : isUploading ? (
              <div className="flex items-center gap-2 text-xs text-blue-600">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Processing network files...</span>
              </div>
            ) : uploadError ? (
              <div className="text-xs text-red-600 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span className="truncate max-w-[180px]">{uploadError}</span>
              </div>
            ) : (
              <div className="text-right">
                <div className="text-xs font-bold text-slate-700">Upload Status</div>
                <div className="text-[10px] text-slate-500">Ready for network files</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
