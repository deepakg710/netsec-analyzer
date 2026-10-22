import React, { useState, useMemo } from 'react';
import { AnalysisRun, Finding, Severity, FindingCategory } from '../../types';
import {
  Search,
  Filter,
  ShieldAlert,
  ArrowRight,
  Download,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Sliders,
  FileCode2,
  Server
} from 'lucide-react';

interface FindingsCenterProps {
  run?: AnalysisRun;
  onSelectFinding: (finding: Finding) => void;
  onExportCsv?: () => void;
  onOpenUploadConfigs?: () => void;
}

export const FindingsCenter: React.FC<FindingsCenterProps> = ({
  run,
  onSelectFinding,
  onExportCsv,
  onOpenUploadConfigs,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedDevice, setSelectedDevice] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 8;

  const findings = run?.findings || [];

  // Extract unique devices
  const availableDevices = useMemo(() => {
    const devs = new Set<string>();
    findings.forEach((f) => {
      if (f.device_id) devs.add(f.device_id);
    });
    return Array.from(devs);
  }, [findings]);

  // Filter findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
      const matchCategory = selectedCategory === 'ALL' || f.category === selectedCategory;
      const matchDevice = selectedDevice === 'ALL' || f.device_id === selectedDevice;
      const matchStatus =
        selectedStatus === 'ALL' ||
        (selectedStatus === 'RESOLVED' && f.is_resolved) ||
        (selectedStatus === 'OPEN' && !f.is_resolved);

      const matchSearch =
        !searchQuery ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.what_is_wrong_professional.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.device_id && f.device_id.toLowerCase().includes(searchQuery.toLowerCase()));

      return matchSeverity && matchCategory && matchDevice && matchStatus && matchSearch;
    });
  }, [findings, selectedSeverity, selectedCategory, selectedDevice, selectedStatus, searchQuery]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredFindings.slice(start, start + pageSize);
  }, [filteredFindings, currentPage, pageSize]);

  const handleExport = () => {
    const csvContent =
      'data:text/csv;charset=utf-8,' +
      ['ID,Severity,Title,Device,Category,Status']
        .concat(
          filteredFindings.map(
            (f) =>
              `"${f.rule_id}","${f.severity}","${f.title.replace(/"/g, '""')}","${f.device_id || 'All'}","${f.category}","${f.is_resolved ? 'Resolved' : 'Open'}"`
          )
        )
        .join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `NetSec_Findings_${run?.id || 'export'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (!run) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600">
          <ShieldAlert className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Findings Available</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Import Cisco configurations or run an analysis to populate the findings and remediation catalog.
        </p>
        {onOpenUploadConfigs && (
          <button
            onClick={onOpenUploadConfigs}
            className="mt-5 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold shadow-sm transition-all flex items-center gap-2"
          >
            <Download className="w-4 h-4 rotate-180" />
            <span>Import Configurations</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 animate-fade-in text-slate-900">
      {/* 1. Header & Quick Summary */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-blue-600" />
            Findings &amp; Remediation Center
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Search, filter, and inspect identified configuration weaknesses with line-numbered Cisco evidence and remediation steps.
          </p>
        </div>

        <button
          onClick={handleExport}
          className="px-4 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-blue-700 text-xs font-bold shadow-xs flex items-center gap-2 transition-all"
        >
          <Download className="w-4 h-4 text-blue-600" />
          <span>Export Findings (.CSV)</span>
        </button>
      </div>

      {/* 2. Top Filter Toolbar matching Reference Screen 5 */}
      <div className="cyber-card p-4 bg-white border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              setCurrentPage(1);
            }}
            className="cyber-input py-1.5 text-xs bg-white text-slate-800"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => {
              setSelectedCategory(e.target.value);
              setCurrentPage(1);
            }}
            className="cyber-input py-1.5 text-xs bg-white text-slate-800"
          >
            <option value="ALL">All Categories</option>
            <option value="ACL / Firewall">ACL / Firewall</option>
            <option value="VLAN / Segmentation">VLAN / Segmentation</option>
            <option value="Routing">Routing</option>
            <option value="Management">Management Access</option>
            <option value="Device Hardening">Device Hardening</option>
            <option value="Resilience & Redundancy">Resilience &amp; Redundancy</option>
          </select>

          {/* Device Dropdown */}
          <select
            value={selectedDevice}
            onChange={(e) => {
              setSelectedDevice(e.target.value);
              setCurrentPage(1);
            }}
            className="cyber-input py-1.5 text-xs bg-white text-slate-800"
          >
            <option value="ALL">All Devices</option>
            {availableDevices.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>

          {/* Status Dropdown */}
          <select
            value={selectedStatus}
            onChange={(e) => {
              setSelectedStatus(e.target.value);
              setCurrentPage(1);
            }}
            className="cyber-input py-1.5 text-xs bg-white text-slate-800"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="cyber-input pl-8 py-1.5 text-xs w-full bg-white text-slate-800"
          />
        </div>
      </div>

      {/* 3. Full-Width Findings Table matching Reference Screen 5 */}
      <div className="cyber-card bg-white border border-slate-200 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-50 text-[10px] uppercase font-bold text-slate-500 border-b border-slate-200">
                <th className="py-3 px-4 w-28">ID</th>
                <th className="py-3 px-4 w-28">Severity</th>
                <th className="py-3 px-4">Title &amp; Observation</th>
                <th className="py-3 px-4 w-32">Device</th>
                <th className="py-3 px-4 w-28 text-center">Status</th>
                <th className="py-3 px-4 w-24 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    <p className="text-xs font-semibold">No findings match your selected filters</p>
                    <p className="text-[11px] text-slate-500 mt-1">Try resetting severity or search query.</p>
                  </td>
                </tr>
              ) : (
                paginatedFindings.map((f) => {
                  const isResolved = f.is_resolved;
                  return (
                    <tr
                      key={f.id}
                      onClick={() => onSelectFinding(f)}
                      className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                    >
                      {/* ID */}
                      <td className="py-3.5 px-4 font-mono font-bold text-blue-700">
                        {f.rule_id}
                      </td>

                      {/* Severity Badge */}
                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            f.severity === 'CRITICAL'
                              ? 'bg-red-50 text-red-700 border border-red-200'
                              : f.severity === 'HIGH'
                              ? 'bg-orange-50 text-orange-700 border border-orange-200'
                              : f.severity === 'MEDIUM'
                              ? 'bg-amber-50 text-amber-800 border border-amber-200'
                              : 'bg-blue-50 text-blue-700 border border-blue-200'
                          }`}
                        >
                          {f.severity}
                        </span>
                      </td>

                      {/* Title & Description */}
                      <td className="py-3.5 px-4">
                        <div className="font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                          {f.title}
                        </div>
                        <div className="text-[11px] text-slate-500 truncate max-w-xl mt-0.5">
                          {f.what_is_wrong_beginner}
                        </div>
                      </td>

                      {/* Device */}
                      <td className="py-3.5 px-4 font-mono text-slate-700">
                        <div className="flex items-center gap-1.5">
                          <Server className="w-3.5 h-3.5 text-slate-400" />
                          <span>{f.device_id || 'Global'}</span>
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4 text-center">
                        {isResolved ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3 h-3" />
                            Resolved
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
                            Open
                          </span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <span className="text-xs font-semibold text-blue-600 group-hover:translate-x-1 inline-flex items-center gap-1 transition-transform">
                          Review &rarr;
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* 4. Pagination Footer matching Reference Screen 5 */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-600">
          <div>
            Showing <span className="font-bold text-slate-900">{Math.min(filteredFindings.length, (currentPage - 1) * pageSize + 1)}</span> to{' '}
            <span className="font-bold text-slate-900">{Math.min(filteredFindings.length, currentPage * pageSize)}</span> of{' '}
            <span className="font-bold text-slate-900">{filteredFindings.length}</span> findings
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-2.5 py-1 rounded bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed text-slate-600 shadow-xs"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>

            {Array.from({ length: totalPages }, (_, i) => i + 1).map((pg) => (
              <button
                key={pg}
                onClick={() => setCurrentPage(pg)}
                className={`px-2.5 py-1 rounded text-xs font-bold transition-all ${
                  currentPage === pg
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 shadow-xs'
                }`}
              >
                {pg}
              </button>
            ))}

            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-2.5 py-1 rounded bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed text-slate-600 shadow-xs"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
