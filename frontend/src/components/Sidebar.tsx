import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Network,
  ShieldAlert,
  GitCommit,
  ListFilter,
  FileSearch,
  Activity,
  GitCompare,
  FileText,
  UserCheck,
  Briefcase,
  Trash2
} from 'lucide-react';

export type NavScreen =
  | 'home'
  | 'topology'
  | 'security'
  | 'attack-path'
  | 'findings'
  | 'remediation-detail'
  | 'resilience'
  | 'comparison'
  | 'reports';

interface SidebarProps {
  currentScreen: NavScreen;
  onSelectScreen: (screen: NavScreen) => void;
  isProfessionalMode: boolean;
  onToggleMode: (isPro: boolean) => void;
  activeProjectName?: string;
  onResetAllData?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentScreen,
  onSelectScreen,
  isProfessionalMode,
  onToggleMode,
  activeProjectName,
  onResetAllData,
}) => {
  const navItems = [
    { id: 'home', label: 'Home / Overview', icon: LayoutDashboard },
    { id: 'topology', label: 'Network Topology', icon: Network },
    { id: 'security', label: 'Security Assessment', icon: ShieldAlert },
    { id: 'attack-path', label: 'Attack-Path Explorer', icon: GitCommit },
    { id: 'findings', label: 'Weakness & Remediation', icon: ListFilter },
    { id: 'remediation-detail', label: 'Detailed Finding View', icon: FileSearch },
    { id: 'resilience', label: 'Resilience & Quality', icon: Activity },
    { id: 'comparison', label: 'Before / After Compare', icon: GitCompare },
    { id: 'reports', label: 'Generate Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col h-screen select-none shrink-0 shadow-sm">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-200 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-600 p-[1px] flex items-center justify-center shadow-md shadow-blue-500/20">
          <div className="w-full h-full bg-blue-50 rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-blue-600" />
          </div>
        </div>
        <div>
          <h1 className="text-sm font-bold text-slate-900 tracking-wide uppercase">NetSec Analyzer</h1>
          <p className="text-[10px] text-blue-600 font-semibold">Design Analysis Engine</p>
        </div>
      </div>

      {/* Mode Switcher */}
      <div className="px-4 py-3 border-b border-slate-200 bg-slate-50">
        <div className="text-[11px] font-semibold text-slate-500 mb-1.5 flex items-center justify-between">
          <span>EXPLANATION DEPTH</span>
          <span className="text-[10px] text-blue-700 font-mono font-bold">
            {isProfessionalMode ? 'PRO' : 'BEGINNER'}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-1 bg-slate-200/80 p-1 rounded-md border border-slate-300">
          <button
            type="button"
            onClick={() => onToggleMode(false)}
            className={`flex items-center justify-center gap-1.5 py-1 px-2 text-xs font-semibold rounded transition-all ${
              !isProfessionalMode
                ? 'bg-white text-blue-700 border border-slate-300 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <UserCheck className="w-3.5 h-3.5" />
            Beginner
          </button>
          <button
            type="button"
            onClick={() => onToggleMode(true)}
            className={`flex items-center justify-center gap-1.5 py-1 px-2 text-xs font-semibold rounded transition-all ${
              isProfessionalMode
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Briefcase className="w-3.5 h-3.5" />
            Pro
          </button>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
          Analysis Views
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentScreen === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectScreen(item.id as NavScreen)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-500/25 font-bold'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span className="truncate">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Project Status & Data Management */}
      <div className="p-3 border-t border-slate-200 bg-slate-50 space-y-2">
        <div>
          <div className="text-[11px] text-slate-500 truncate">
            Active Project:
          </div>
          <div className="text-xs font-semibold text-slate-800 truncate flex items-center gap-1.5 mt-0.5">
            <span className={`w-2 h-2 rounded-full inline-block ${activeProjectName ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`}></span>
            {activeProjectName || 'No Project Active (0)'}
          </div>
        </div>

        <div className="pt-2 flex items-center justify-between border-t border-slate-200 text-[10px]">
          <span className="text-slate-500 font-mono">SQLite Local DB</span>
          {onResetAllData && (
            <button
              onClick={onResetAllData}
              title="Wipe all projects and reset to 0"
              className="text-red-600 hover:text-red-700 flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-red-50 transition-colors font-semibold"
            >
              <Trash2 className="w-3 h-3" />
              Reset to 0
            </button>
          )}
        </div>
      </div>
    </aside>
  );
};
