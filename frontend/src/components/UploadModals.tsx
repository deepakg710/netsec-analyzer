import React, { useState } from 'react';
import { apiClient } from '../api/client';
import {
  Upload,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileText,
  Info,
  Terminal,
  ArrowRight,
  Shield,
  Zap,
  HelpCircle,
  Copy,
  Check,
  RefreshCw,
  Plus
} from 'lucide-react';

interface UploadModalsProps {
  projectId: string;
  isOpenConfigs: boolean;
  isOpenPkt: boolean;
  onClose: () => void;
  onSuccess: (createdProjectId?: string) => void;
  onLoadSample?: (type: 'vulnerable' | 'hardened' | 'large_enterprise') => void;
}

export const UploadModals: React.FC<UploadModalsProps> = ({
  projectId,
  isOpenConfigs,
  isOpenPkt,
  onClose,
  onSuccess,
  onLoadSample,
}) => {
  // Config Upload states
  const [activeConfigTab, setActiveConfigTab] = useState<'upload' | 'paste'>('upload');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [pasteFilename, setPasteFilename] = useState('Router_R1.cfg');
  const [pasteContent, setPasteContent] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // PKT Upload states
  const [pktFile, setPktFile] = useState<File | null>(null);
  const [pktReport, setPktReport] = useState<any | null>(null);
  const [isInspectingPkt, setIsInspectingPkt] = useState(false);
  const [pktPasteName, setPktPasteName] = useState('Router_R1.cfg');
  const [pktPasteContent, setPktPasteContent] = useState('');
  const [isPktPasting, setIsPktPasting] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const handleCopyCmd = () => {
    navigator.clipboard.writeText('show running-config');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleConfigUpload = async () => {
    const targetProjId = projectId && projectId.trim() ? projectId : 'new';
    if (activeConfigTab === 'upload') {
      if (!selectedFiles.length) return;
      setIsUploading(true);
      setErrorMsg('');
      try {
        const res = await apiClient.uploadConfigs(targetProjId, selectedFiles);
        const resolvedId = res.project_id || targetProjId;
        try {
          await apiClient.runAnalysis(resolvedId);
        } catch (analysisErr) {
          console.warn('Initial auto-analysis warning:', analysisErr);
        }
        onSuccess(resolvedId);
        onClose();
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to upload configurations');
      } finally {
        setIsUploading(false);
      }
    } else {
      if (!pasteContent.trim()) return;
      setIsUploading(true);
      setErrorMsg('');
      try {
        const res = await apiClient.pasteConfig(targetProjId, pasteFilename, pasteContent);
        const resolvedId = res.project_id || targetProjId;
        try {
          await apiClient.runAnalysis(resolvedId);
        } catch (analysisErr) {
          console.warn('Initial auto-analysis warning:', analysisErr);
        }
        onSuccess(resolvedId);
        onClose();
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to ingest configuration snippet');
      } finally {
        setIsUploading(false);
      }
    }
  };

  const handlePktUpload = async () => {
    if (!pktFile) return;
    setIsInspectingPkt(true);
    setPktReport(null);
    setErrorMsg('');
    const targetProjId = projectId && projectId.trim() ? projectId : 'new';
    try {
      const res = await apiClient.uploadPkt(targetProjId, pktFile);
      setPktReport(res);
      if (res.extracted_devices_count > 0) {
        onSuccess(res.project_id);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to inspect Packet Tracer file');
    } finally {
      setIsInspectingPkt(false);
    }
  };

  const handlePktPasteSubmit = async (addAnother: boolean = false) => {
    if (!pktPasteContent.trim()) return;
    setIsPktPasting(true);
    setErrorMsg('');
    const targetProjId = pktReport?.project_id || (projectId && projectId.trim() ? projectId : 'new');
    try {
      const res = await apiClient.pasteConfig(targetProjId, pktPasteName, pktPasteContent);
      const projId = res.project_id || targetProjId;
      if (addAnother) {
        setPktPasteName(pktPasteName.includes('Router') ? 'Switch1.cfg' : 'Device.cfg');
        setPktPasteContent('');
        alert(`Successfully added ${pktPasteName}! Paste your next device config.`);
      } else {
        await apiClient.runAnalysis(projId);
        onSuccess(projId);
        onClose();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to ingest configuration snippet');
    } finally {
      setIsPktPasting(false);
    }
  };

  if (!isOpenConfigs && !isOpenPkt) return null;

  return (
    <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
      <div className="cyber-card max-w-2xl w-full p-6 shadow-2xl relative max-h-[92vh] overflow-y-auto bg-white border border-slate-200 text-slate-800">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-900 text-xs font-bold px-2 py-1 rounded bg-slate-100 border border-slate-200"
        >
          ✕
        </button>

        {isOpenConfigs && (
          <div className="space-y-5">
            <div className="border-b border-slate-200 pb-3">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <FileCode2 className="w-5 h-5 text-blue-600" />
                Import Cisco Configurations
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Supports Cisco IOS <code className="text-blue-700 font-mono font-semibold">running-config</code> exports and show commands.
              </p>
            </div>

            {/* Tabs: Upload vs Paste */}
            <div className="grid grid-cols-2 gap-2 bg-slate-100 p-1 rounded-lg border border-slate-200">
              <button
                onClick={() => setActiveConfigTab('upload')}
                className={`py-1.5 text-xs font-semibold rounded transition-all ${
                  activeConfigTab === 'upload'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Upload Files (.cfg, .txt)
              </button>
              <button
                onClick={() => setActiveConfigTab('paste')}
                className={`py-1.5 text-xs font-semibold rounded transition-all ${
                  activeConfigTab === 'paste'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Paste Configuration Text
              </button>
            </div>

            {activeConfigTab === 'upload' ? (
              <div className="space-y-4">
                <div className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-xl p-8 text-center bg-slate-50 transition-colors">
                  <Upload className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                  <div className="text-xs font-bold text-slate-800">
                    Click to select configuration files
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Accepts multiple files (.cfg, .txt, .conf - up to 10MB each)
                  </div>
                  <input
                    type="file"
                    multiple
                    accept=".cfg,.txt,.conf,.log"
                    onChange={(e) => setSelectedFiles(Array.from(e.target.files || []))}
                    className="mt-3 text-xs text-slate-600 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
                  />
                </div>

                {selectedFiles.length > 0 && (
                  <div className="text-xs text-slate-700 bg-slate-50 p-3 rounded-lg border border-slate-200">
                    Selected <strong className="text-blue-700">{selectedFiles.length}</strong> file(s):{' '}
                    <span className="font-mono text-[11px] text-slate-600">
                      {selectedFiles.map((f) => f.name).join(', ')}
                    </span>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="text-[11px] font-bold text-slate-600 uppercase">Device / File Name:</label>
                  <input
                    type="text"
                    value={pasteFilename}
                    onChange={(e) => setPasteFilename(e.target.value)}
                    placeholder="Router_R1.cfg"
                    className="cyber-input w-full text-xs mt-1"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-bold text-slate-600 uppercase">Configuration Text:</label>
                  <textarea
                    rows={8}
                    value={pasteContent}
                    onChange={(e) => setPasteContent(e.target.value)}
                    placeholder="hostname Branch-R1&#10;interface GigabitEthernet0/0&#10; ip address 192.168.1.1 255.255.255.0&#10; no shutdown&#10;interface GigabitEthernet0/1&#10; ip address 192.168.30.1 255.255.255.0..."
                    className="cyber-input w-full text-xs font-mono mt-1"
                  />
                </div>
              </div>
            )}

            {errorMsg && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs">
                {errorMsg}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleConfigUpload}
                disabled={isUploading || (activeConfigTab === 'upload' ? !selectedFiles.length : !pasteContent.trim())}
                className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-bold shadow-sm"
              >
                {isUploading ? 'Ingesting...' : 'Ingest & Parse'}
              </button>
            </div>
          </div>
        )}

        {isOpenPkt && (
          <div className="space-y-4">
            <div className="border-b border-slate-200 pb-3">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <Upload className="w-5 h-5 text-blue-600" />
                Analyze Cisco Packet Tracer Network
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Inspect .pkt container or import running-configurations from Packet Tracer.
              </p>
            </div>

            {/* If no report yet, show file picker */}
            {!pktReport ? (
              <div className="space-y-3">
                <div className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-xl p-6 text-center bg-slate-50 transition-colors">
                  <Upload className="w-8 h-8 text-blue-600 mx-auto mb-2" />
                  <div className="text-xs font-bold text-slate-800">Select .pkt File</div>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Packet Tracer .pkt, .pka, and .pkz files
                  </p>
                  <input
                    type="file"
                    accept=".pkt,.pka,.pkz"
                    onChange={(e) => setPktFile(e.target.files?.[0] || null)}
                    className="mt-3 text-xs text-slate-600 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700"
                  />
                </div>

                {pktFile && (
                  <div className="flex items-center justify-between text-xs text-slate-700 bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                    <span className="font-mono">
                      Selected: <strong className="text-blue-700">{pktFile.name}</strong> ({Math.round(pktFile.size / 1024)} KB)
                    </span>
                    <button
                      onClick={handlePktUpload}
                      disabled={isInspectingPkt}
                      className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-bold shadow-sm"
                    >
                      {isInspectingPkt ? 'Inspecting...' : 'Analyze .pkt'}
                    </button>
                  </div>
                )}
              </div>
            ) : (
              /* Compact inspection banner once inspected */
              <div className="flex items-center justify-between p-2.5 rounded bg-slate-50 border border-slate-200 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">File:</span>
                  <span className="font-mono text-blue-700 font-semibold">{pktFile?.name}</span>
                  <span className="text-slate-400 text-[11px]">({Math.round((pktFile?.size || 0) / 1024)} KB)</span>
                </div>
                <button
                  onClick={() => {
                    setPktReport(null);
                    setPktFile(null);
                  }}
                  className="text-xs text-blue-600 hover:text-blue-800 underline"
                >
                  Choose different file
                </button>
              </div>
            )}

            {/* Inspection Results Report */}
            {pktReport && (
              <div className="space-y-3 animate-fade-in">
                {/* Informative Banner */}
                <div className="p-3 rounded-lg border border-blue-200 bg-blue-50 text-xs text-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-blue-800 flex items-center gap-1.5">
                      <Info className="w-4 h-4 text-blue-600" />
                      Packet Tracer 8/9 Encrypted Container Detected
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-100 text-blue-700 border border-blue-200 font-semibold">
                      Zero-Fabrication Mode
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 leading-relaxed">
                    Cisco Packet Tracer v8/v9 encrypts simulation files with proprietary DRM keys.
                    To guarantee 100% precision with zero fabricated data, copy your configuration from Packet Tracer:
                  </p>
                </div>

                {/* 3-Step Guide & Direct Paste Area */}
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-blue-600" />
                      Import Configuration from Packet Tracer CLI:
                    </div>
                    <button
                      onClick={handleCopyCmd}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-white hover:bg-slate-100 text-[11px] text-blue-700 border border-slate-200 shadow-xs font-semibold transition-all"
                    >
                      {copiedCmd ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      {copiedCmd ? 'Copied!' : 'Copy "show running-config"'}
                    </button>
                  </div>

                  {/* 3 Quick Steps */}
                  <div className="grid grid-cols-3 gap-2 text-[10px] text-slate-700">
                    <div className="p-2 rounded bg-white border border-slate-200">
                      <strong className="text-blue-600">1.</strong> Click Router/Switch in Packet Tracer
                    </div>
                    <div className="p-2 rounded bg-white border border-slate-200">
                      <strong className="text-blue-600">2.</strong> In <span className="text-slate-900 font-bold">CLI</span> tab, run <code className="text-blue-700 font-mono">show run</code>
                    </div>
                    <div className="p-2 rounded bg-white border border-slate-200">
                      <strong className="text-blue-600">3.</strong> Paste output below &amp; analyze
                    </div>
                  </div>

                  {/* Input Fields */}
                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between">
                      <label className="text-[10px] font-bold text-slate-600 uppercase">Device Name / File:</label>
                      <input
                        type="text"
                        value={pktPasteName}
                        onChange={(e) => setPktPasteName(e.target.value)}
                        className="cyber-input text-xs py-1 px-2 w-44 font-mono"
                        placeholder="Router_R1.cfg"
                      />
                    </div>
                    <textarea
                      rows={7}
                      value={pktPasteContent}
                      onChange={(e) => setPktPasteContent(e.target.value)}
                      placeholder="Paste running-config text here...&#10;Example:&#10;hostname R1&#10;interface GigabitEthernet0/0&#10; ip address 192.168.1.1 255.255.255.0&#10; no shutdown&#10;interface GigabitEthernet0/1&#10; ip address 192.168.30.1 255.255.255.0&#10; no shutdown&#10;ip route 0.0.0.0 0.0.0.0 203.0.113.1"
                      className="cyber-input w-full text-xs font-mono"
                    />
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-200">
                    {onLoadSample && (
                      <button
                        type="button"
                        onClick={() => {
                          onClose();
                          onLoadSample('vulnerable');
                        }}
                        className="text-xs text-amber-700 hover:text-amber-800 underline flex items-center gap-1 font-semibold"
                      >
                        <Zap className="w-3.5 h-3.5 text-amber-600" />
                        Explore with Sample Network (1-Click)
                      </button>
                    )}

                    <div className="flex items-center gap-2 ml-auto">
                      <button
                        type="button"
                        onClick={() => handlePktPasteSubmit(true)}
                        disabled={isPktPasting || !pktPasteContent.trim()}
                        className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-semibold flex items-center gap-1 shadow-xs"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        Add Another Device
                      </button>

                      <button
                        type="button"
                        onClick={() => handlePktPasteSubmit(false)}
                        disabled={isPktPasting || !pktPasteContent.trim()}
                        className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-bold shadow-sm flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {isPktPasting ? 'Ingesting...' : 'Ingest & Run Analysis'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {errorMsg && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs">
                {errorMsg}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-1">
              <button
                onClick={onClose}
                className="px-4 py-1.5 rounded-lg bg-slate-100 text-slate-700 text-xs font-semibold hover:bg-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
