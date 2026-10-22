import React, { useState, useMemo, useCallback, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  Handle,
  Position,
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { TopologyData, AnalysisRun } from '../../types';
import {
  Cloud,
  Shield,
  Layers,
  Terminal,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Sliders,
  Laptop,
  Server as ServerIcon,
  Database,
  Globe,
  Network,
  CheckCircle2,
  Upload
} from 'lucide-react';

// --- Specialized Cisco-Style SVG Icons ---

// Cisco Router Icon (Cylindrical with 4 arrows)
const CiscoRouterIcon = ({ className = 'w-7 h-7 text-blue-600' }: { className?: string }) => (
  <svg viewBox="0 0 40 40" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
    <ellipse cx="20" cy="20" rx="17" ry="17" fill="#eff6ff" stroke="currentColor" strokeWidth="2" />
    <ellipse cx="20" cy="20" rx="14" ry="14" fill="#dbeafe" stroke="#3b82f6" strokeWidth="1" strokeDasharray="2 2" />
    {/* 4 Inward/Outward Arrows */}
    <path d="M12 20H8M8 20L10 17M8 20L10 23" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M28 20H32M32 20L30 17M32 20L30 23" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M20 12V8M20 8L17 10M20 8L23 10" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M20 28V32M20 32L17 30M20 32L23 30" stroke="#2563eb" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// Cisco Switch Icon (Box with bidirectional cross-arrows)
const CiscoSwitchIcon = ({ className = 'w-7 h-7 text-emerald-600' }: { className?: string }) => (
  <svg viewBox="0 0 40 40" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="5" y="8" width="30" height="24" rx="4" fill="#ecfdf5" stroke="currentColor" strokeWidth="2" />
    <path d="M12 16H28M28 16L24 13M28 16L24 19" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M28 24H12M12 24L16 21M12 24L16 27" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// Cisco Firewall Icon (Red Cube with Wall/Shield)
const CiscoFirewallIcon = ({ className = 'w-7 h-7 text-red-600' }: { className?: string }) => (
  <svg viewBox="0 0 40 40" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect x="6" y="8" width="28" height="24" rx="3" fill="#fef2f2" stroke="currentColor" strokeWidth="2" />
    <line x1="6" y1="16" x2="34" y2="16" stroke="currentColor" strokeWidth="1.5" />
    <line x1="6" y1="24" x2="34" y2="24" stroke="currentColor" strokeWidth="1.5" />
    <line x1="16" y1="8" x2="16" y2="16" stroke="currentColor" strokeWidth="1.5" />
    <line x1="24" y1="8" x2="24" y2="16" stroke="currentColor" strokeWidth="1.5" />
    <line x1="20" y1="16" x2="20" y2="24" stroke="currentColor" strokeWidth="1.5" />
    <line x1="14" y1="24" x2="14" y2="32" stroke="currentColor" strokeWidth="1.5" />
    <line x1="26" y1="24" x2="26" y2="32" stroke="currentColor" strokeWidth="1.5" />
  </svg>
);

// --- Custom React Flow Node Components ---

// 1. Internet Cloud Node (Reference Screen 2)
const CloudNode = ({ data }: any) => {
  return (
    <div className="px-6 py-2.5 rounded-full bg-blue-50 border-2 border-blue-400 shadow-md flex items-center gap-2.5 text-center justify-center">
      <Cloud className="w-5 h-5 text-blue-600" />
      <span className="text-xs font-bold text-slate-800 tracking-wide">{data.label || 'Internet'}</span>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-blue-500" />
    </div>
  );
};

// 2. Firewall Node (Red box matching Reference Screen 2)
const FirewallNode = ({ data, selected }: any) => {
  return (
    <div
      className={`px-4 py-2.5 rounded-xl bg-white border-2 ${
        selected ? 'border-red-500 ring-2 ring-red-400/40 shadow-xl' : 'border-red-400'
      } flex items-center gap-2.5 shadow-md min-w-[130px]`}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-red-500" />
      <CiscoFirewallIcon className="w-6 h-6 text-red-600 shrink-0" />
      <div>
        <div className="text-xs font-bold text-slate-900">{data.label || 'Firewall'}</div>
        <div className="text-[10px] text-red-600 font-mono font-medium">ASA / Perimeter</div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-red-500" />
    </div>
  );
};

// 3. Router Node (Blue cylinder matching Reference Screen 2)
const RouterNode = ({ data, selected }: any) => {
  return (
    <div
      className={`px-4 py-2.5 rounded-xl bg-white border-2 ${
        selected ? 'border-blue-600 ring-2 ring-blue-400/40 shadow-xl' : 'border-blue-400'
      } flex items-center gap-2.5 shadow-md min-w-[130px]`}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-blue-600" />
      <CiscoRouterIcon className="w-6 h-6 text-blue-600 shrink-0" />
      <div>
        <div className="text-xs font-bold text-slate-900">{data.label || 'R1'}</div>
        <div className="text-[10px] text-blue-600 font-mono font-medium">{data.model || 'ISR4331'}</div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-blue-600" />
    </div>
  );
};

// 4. Switch Node (Green/Blue box matching Reference Screen 2)
const SwitchNode = ({ data, selected }: any) => {
  return (
    <div
      className={`px-4 py-2.5 rounded-xl bg-white border-2 ${
        selected ? 'border-emerald-600 ring-2 ring-emerald-400/40 shadow-xl' : 'border-emerald-400'
      } flex items-center gap-2.5 shadow-md min-w-[135px]`}
    >
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-emerald-600" />
      <CiscoSwitchIcon className="w-6 h-6 text-emerald-600 shrink-0" />
      <div>
        <div className="text-xs font-bold text-slate-900">{data.label || 'Core-SW1'}</div>
        <div className="text-[10px] text-emerald-600 font-mono font-medium">Switch</div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-emerald-600" />
    </div>
  );
};

// 5. VLAN Group Container Node matching Reference Screen 2
const VlanGroupNode = ({ data }: any) => {
  const vlanColors: Record<number, { border: string; bg: string; badge: string; text: string }> = {
    10: { border: 'border-emerald-300', bg: 'bg-emerald-50/70', badge: 'bg-emerald-100 text-emerald-800', text: 'text-emerald-700' },
    20: { border: 'border-blue-300', bg: 'bg-blue-50/70', badge: 'bg-blue-100 text-blue-800', text: 'text-blue-700' },
    30: { border: 'border-amber-300', bg: 'bg-amber-50/70', badge: 'bg-amber-100 text-amber-800', text: 'text-amber-700' },
    40: { border: 'border-purple-300', bg: 'bg-purple-50/70', badge: 'bg-purple-100 text-purple-800', text: 'text-purple-700' },
  };

  const vId = Number(data.vlanId) || 10;
  const cfg = vlanColors[vId] || vlanColors[10];

  return (
    <div className={`p-4 rounded-2xl ${cfg.bg} border-2 ${cfg.border} shadow-sm min-w-[210px] text-center`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-blue-600" />
      {/* Header */}
      <div className="border-b border-slate-200/80 pb-2 mb-3">
        <div className="text-xs font-bold text-slate-900 tracking-wide">{data.name || `VLAN ${vId} Users`}</div>
        <div className={`text-[10px] font-mono font-bold mt-0.5 ${cfg.text}`}>{data.subnet || '192.168.10.0/24'}</div>
      </div>

      {/* Endpoints inside container */}
      <div className="flex items-center justify-center gap-2.5">
        {(data.endpoints || ['PC1', 'PC2', 'PC3']).map((ep: string, i: number) => (
          <div key={i} className="flex flex-col items-center gap-1">
            <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 shadow-xs flex items-center justify-center text-slate-700 hover:text-blue-600 transition-colors">
              {ep.toLowerCase().includes('server') ? (
                <ServerIcon className="w-4 h-4 text-blue-600" />
              ) : ep.toLowerCase().includes('db') ? (
                <Database className="w-4 h-4 text-amber-600" />
              ) : ep.toLowerCase().includes('web') ? (
                <Globe className="w-4 h-4 text-emerald-600" />
              ) : (
                <Laptop className="w-4 h-4 text-blue-600" />
              )}
            </div>
            <span className="text-[10px] text-slate-700 font-mono font-semibold">{ep}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const nodeTypes = {
  cloudNode: CloudNode,
  firewallNode: FirewallNode,
  routerNode: RouterNode,
  switchNode: SwitchNode,
  vlanGroupNode: VlanGroupNode,
};

interface TopologyViewProps {
  topologyData?: TopologyData;
  run?: AnalysisRun;
  onLoadSample?: (type: 'vulnerable' | 'hardened' | 'large_enterprise') => void;
  onOpenUploadConfigs?: () => void;
}

const TopologyCanvas: React.FC<TopologyViewProps> = ({ topologyData, run, onLoadSample, onOpenUploadConfigs }) => {
  const [selectedDevice, setSelectedDevice] = useState<any | null>(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [filterVlan, setFilterVlan] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const { fitView, zoomIn, zoomOut } = useReactFlow();

  // Build Topology Nodes & Edges from real topologyData
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!topologyData || !topologyData.nodes || topologyData.nodes.length === 0) {
      return { initialNodes: [], initialEdges: [] };
    }

    const nodes: Node[] = topologyData.nodes.map((n: any) => {
      let nodeType = n.type || 'switchNode';
      const devType = (n.data?.deviceType || '').toUpperCase();
      const labelLower = (n.data?.label || '').toLowerCase();

      if (n.id === 'internet_cloud' || devType === 'INTERNET' || labelLower.includes('internet')) {
        nodeType = 'cloudNode';
      } else if (devType === 'FIREWALL' || labelLower.includes('firewall') || labelLower.includes('asa')) {
        nodeType = 'firewallNode';
      } else if (devType === 'ROUTER' || labelLower.startsWith('r') || labelLower.includes('router') || labelLower.includes('edge')) {
        nodeType = 'routerNode';
      } else if (devType === 'SWITCH' || labelLower.includes('switch') || labelLower.includes('sw')) {
        nodeType = 'switchNode';
      }

      return {
        id: n.id,
        type: nodeType,
        position: n.position || { x: 200, y: 200 },
        data: n.data || { label: n.id },
      };
    });

    const edges: Edge[] = (topologyData.edges || []).map((e: any) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label || '',
      type: 'smoothstep',
      animated: e.animated || false,
      style: e.style || { stroke: '#0284c7', strokeWidth: 2 },
      data: e.data,
      labelStyle: { fill: '#0369a1', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 },
      labelBgStyle: { fill: '#f8fafc', fillOpacity: 0.9, stroke: '#cbd5e1', rx: 4, ry: 4 },
    }));

    return { initialNodes: nodes, initialEdges: edges };
  }, [topologyData]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  // Filter nodes by VLAN and Search
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      const data = n.data as any;
      const label = data?.label || data?.name || '';
      const matchSearch =
        !searchTerm ||
        label.toLowerCase().includes(searchTerm.toLowerCase()) ||
        String(n.id).toLowerCase().includes(searchTerm.toLowerCase());

      const matchVlan =
        filterVlan === 'all' ||
        (n.type === 'vlanGroupNode' && String(data.vlanId) === String(filterVlan)) ||
        n.type !== 'vlanGroupNode';

      return matchSearch && matchVlan;
    });
  }, [nodes, searchTerm, filterVlan]);

  const handleNodeClick = (_: any, node: Node) => {
    if (node.data) {
      setSelectedDevice({
        ...node.data,
        id: node.id,
      });
    }
  };

  if (initialNodes.length === 0) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center p-8 text-center bg-slate-50 text-slate-900">
        <div className="w-16 h-16 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center mb-4 text-blue-600 shadow-sm">
          <Network className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 tracking-wide">No Network Topology Available</h2>
        <p className="text-xs text-slate-500 max-w-md mt-2 leading-relaxed">
          Upload Cisco IOS configuration files (.cfg, .txt) or paste running-configs to automatically reconstruct and visualize the interactive network diagram.
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
          {onLoadSample && (
            <button
              onClick={() => onLoadSample('large_enterprise')}
              className="px-5 py-2.5 rounded-xl bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-bold shadow-xs transition-all"
            >
              Load Sample Network
            </button>
          )}
        </div>
      </div>
    );
  }


  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col bg-slate-50 relative select-none">
      {/* Top Controls Toolbar matching Reference Screen 2 */}
      <div className="h-12 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0 z-10 shadow-xs">
        <div className="flex items-center gap-3">
          {/* Layout Selector */}
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Sliders className="w-3.5 h-3.5 text-blue-600" />
            <span className="font-semibold text-slate-700">Layout:</span>
            <select className="cyber-input py-1 text-xs bg-white text-slate-800">
              <option>Hierarchical</option>
              <option>Force-Directed</option>
              <option>Orthogonal</option>
            </select>
          </div>

          {/* Zoom Controls */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200">
            <button
              onClick={() => zoomIn()}
              title="Zoom In"
              className="p-1 text-slate-600 hover:text-blue-600 transition-colors"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => zoomOut()}
              title="Zoom Out"
              className="p-1 text-slate-600 hover:text-blue-600 transition-colors"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => fitView()}
              title="Fit View"
              className="p-1 text-slate-600 hover:text-blue-600 transition-colors"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* VLAN Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Layers className="w-3.5 h-3.5 text-blue-600" />
            <span className="font-semibold text-slate-700">Filter VLANs:</span>
            <select
              value={filterVlan}
              onChange={(e) => setFilterVlan(e.target.value)}
              className="cyber-input py-1 text-xs bg-white text-slate-800"
            >
              <option value="all">All VLANs (4)</option>
              <option value="10">VLAN 10 (Users)</option>
              <option value="20">VLAN 20 (Servers)</option>
              <option value="30">VLAN 30 (DMZ)</option>
              <option value="40">VLAN 40 (Guest)</option>
            </select>
          </div>

          {/* Search Devices */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search devices..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="cyber-input pl-8 py-1 text-xs w-44 bg-white text-slate-800"
            />
          </div>
        </div>

        {/* Link Legend matching Reference Screen 2 */}
        <div className="flex items-center gap-6 text-xs font-semibold">
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="w-4 h-0.5 bg-emerald-500"></span>
            <span>Normal Link</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="w-4 h-0.5 border-t-2 border-dashed border-emerald-500"></span>
            <span>Trunk Link</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-600">
            <span className="w-3 h-3 rounded border border-purple-400 bg-purple-100"></span>
            <span>VLAN Boundary</span>
          </div>
        </div>
      </div>

      {/* Main Flow Canvas & Right Device Details Drawer */}
      <div className="flex-1 flex overflow-hidden relative">
        <div className="flex-1 h-full relative">
          <ReactFlow
            nodes={filteredNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            nodeTypes={nodeTypes}
            fitView
            className="bg-slate-50"
          >
            <Background color="#cbd5e1" gap={22} size={1} />
            <Controls className="!bg-white !border-slate-200 !text-slate-700 !rounded-xl shadow-md" />
          </ReactFlow>
        </div>

        {/* Right Device Details Drawer matching Reference Screen 2 */}
        {selectedDevice && (
          <aside className="w-80 bg-white border-l border-slate-200 flex flex-col h-full overflow-y-auto p-5 shrink-0 animate-slide-left z-20 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
                  <CiscoRouterIcon className="w-5 h-5 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">{selectedDevice.label || selectedDevice.name}</h3>
                  <div className="text-[10px] text-blue-600 font-mono font-semibold">
                    {selectedDevice.deviceType || 'Router'} | {selectedDevice.model || 'Cisco 2911'}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedDevice(null)}
                className="w-6 h-6 rounded-md hover:bg-slate-100 text-slate-400 hover:text-slate-700 flex items-center justify-center text-xs"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs">
              {/* Properties matching Reference Screen 2 */}
              <div className="space-y-1.5 bg-slate-50 p-3 rounded-xl border border-slate-200">
                <div className="flex justify-between text-slate-500">
                  <span>Hostname:</span>
                  <span className="font-mono text-slate-800 font-bold">{selectedDevice.label || selectedDevice.name}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Model:</span>
                  <span className="font-mono text-slate-800">{selectedDevice.model || 'ISR4331'}</span>
                </div>
                <div className="flex justify-between text-slate-500">
                  <span>Interfaces:</span>
                  <span className="font-mono text-blue-700 font-bold">
                    {selectedDevice.interfaces?.length || 6}
                  </span>
                </div>
              </div>

              {/* Connected Networks matching Reference Screen 2 */}
              <div>
                <div className="font-bold text-slate-800 mb-2">Connected Networks</div>
                <div className="space-y-1.5">
                  {(selectedDevice.connectedNetworks || [
                    'Gi0/0 - 10.10.1.1/30 (up)',
                    'Gi0/1 - 192.168.10.1/24 (up)',
                    'Se0/0/0 - 10.10.20.1/30 (up)',
                  ]).map((net: string, idx: number) => (
                    <div
                      key={idx}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-[11px] text-slate-700 flex items-center justify-between"
                    >
                      <span className="text-blue-700 font-semibold">{net}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Findings matching Reference Screen 2 */}
              <div>
                <div className="font-bold text-slate-800 mb-2">Security Findings</div>
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-slate-700">
                      <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
                      High
                    </span>
                    <span className="font-mono font-bold text-orange-600">2</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-slate-700">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                      Medium
                    </span>
                    <span className="font-mono font-bold text-amber-600">1</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-slate-700">
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
                      Low
                    </span>
                    <span className="font-mono font-bold text-blue-600">0</span>
                  </div>
                </div>
              </div>

              {/* View Configuration Button */}
              <div className="pt-2">
                <button
                  onClick={() => setShowConfigModal(true)}
                  className="w-full py-2.5 px-3 rounded-xl bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-700 font-semibold text-xs flex items-center justify-center gap-2 transition-all shadow-xs"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  View Configuration
                </button>
              </div>
            </div>
          </aside>
        )}
      </div>

      {/* Raw Config Modal */}
      {showConfigModal && selectedDevice && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-6 z-50">
          <div className="cyber-card max-w-2xl w-full max-h-[80vh] flex flex-col p-6 shadow-2xl bg-white border border-slate-200">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-600" />
                Cisco IOS Configuration — {selectedDevice.label || selectedDevice.name}
              </h3>
              <button
                onClick={() => setShowConfigModal(false)}
                className="text-slate-500 hover:text-slate-800 text-xs px-2 py-1 rounded hover:bg-slate-100"
              >
                ✕ Close
              </button>
            </div>
            <pre className="flex-1 bg-slate-900 p-4 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 overflow-y-auto leading-relaxed">
              {`! Cisco IOS Configuration for ${selectedDevice.label || selectedDevice.name}\n` +
                `hostname ${selectedDevice.label || selectedDevice.name}\n!\n` +
                (selectedDevice.interfaces || [
                  { name: 'GigabitEthernet0/0', ip: '10.10.1.1', mask: '255.255.255.252' },
                  { name: 'GigabitEthernet0/1', ip: '192.168.10.1', mask: '255.255.255.0' },
                  { name: 'Serial0/0/0', ip: '10.10.20.1', mask: '255.255.255.252' },
                ])
                  .map(
                    (i: any) =>
                      `interface ${i.name}\n` +
                      (i.ip && i.ip !== 'unassigned' && i.ip !== 'trunk' ? ` ip address ${i.ip} ${i.mask || '255.255.255.0'}\n` : '') +
                      (i.ip === 'trunk' ? ` switchport mode trunk\n` : '') +
                      (i.vlan ? ` switchport access vlan ${i.vlan}\n` : '') +
                      (i.aclIn ? ` ip access-group ${i.aclIn} in\n` : '') +
                      (i.isShutdown ? ' shutdown\n' : ' no shutdown\n') +
                      '!'
                  )
                  .join('\n')}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export const TopologyView: React.FC<TopologyViewProps> = (props) => {
  return (
    <ReactFlowProvider>
      <TopologyCanvas {...props} />
    </ReactFlowProvider>
  );
};
