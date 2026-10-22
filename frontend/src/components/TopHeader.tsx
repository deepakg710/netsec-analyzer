import React from 'react';
import { NavScreen } from './Sidebar';
import { Network, ShieldAlert, FileText, Server, RefreshCw, Upload, FolderPlus } from 'lucide-react';

interface TopHeaderProps {
  currentScreen: NavScreen;
  onSelectScreen: (screen: NavScreen) => void;
  projectName?: string;
  isAnalyzing: boolean;
  onTriggerAnalysis: () => void;
  onOpenUploadModal: () => void;
  onCreateNewProject?: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  currentScreen,
  onSelectScreen,
  projectName,
  isAnalyzing,
  onTriggerAnalysis,
  onOpenUploadModal,
  onCreateNewProject,
}) => {
  const tabs = [
    { id: 'topology', label: 'Topology', icon: Network },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'resilience', label: 'Devices / Health', icon: Server },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const getScreenTitle = () => {
    switch (currentScreen) {
      case 'home':
        return 'Home Dashboard';
      case 'topology':
        return 'Network Topology Visualization';
      case 'security':
        return 'Security Assessment';
      case 'attack-path':
        return 'Attack-Path Explorer';
      case 'findings':
        return 'Weakness and Remediation Center';
      case 'remediation-detail':
        return 'Detailed Finding & Remediation View';
      case 'resilience':
        return 'Resilience and Network Quality';
      case 'comparison':
        return 'Before / After Comparison';
      case 'reports':
        return 'Assessment Report Generator';
      default:
        return 'Dashboard';
    }
  };

  return (
    <header className="h-14 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0 shadow-xs">
      {/* Title & Project Pill */}
      <div className="flex items-center gap-3">
        <span className="text-xs font-semibold text-slate-500">NetSec Analyzer</span>
        <span className="text-slate-300">/</span>
        <h2 className="text-sm font-bold text-slate-900">{getScreenTitle()}</h2>

        {projectName ? (
          <span className="ml-2 px-2.5 py-0.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-mono font-semibold">
            {projectName}
          </span>
        ) : (
          <span className="ml-2 px-2.5 py-0.5 rounded-full bg-slate-100 border border-slate-300 text-slate-500 text-xs font-mono">
            No Active Project (0)
          </span>
        )}
      </div>

      {/* Middle Reference Image Tabs */}
      <div className="hidden md:flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentScreen === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectScreen(tab.id as NavScreen)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/70'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Action Buttons */}
      <div className="flex items-center gap-2">
        {onCreateNewProject && (
          <button
            onClick={onCreateNewProject}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 hover:bg-blue-100 border border-blue-200 text-xs font-semibold text-blue-700 transition-all shadow-xs"
          >
            <FolderPlus className="w-3.5 h-3.5" />
            + New Project
          </button>
        )}

        <button
          onClick={onOpenUploadModal}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-xs font-semibold text-slate-700 transition-all shadow-xs"
        >
          <Upload className="w-3.5 h-3.5 text-blue-600" />
          Import
        </button>

        <button
          onClick={onTriggerAnalysis}
          disabled={isAnalyzing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold shadow-sm transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
          {isAnalyzing ? 'Analyzing...' : 'Re-Analyze'}
        </button>
      </div>
    </header>
  );
};
