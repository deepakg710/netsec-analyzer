import React, { useState, useEffect } from 'react';
import { Sidebar, NavScreen } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { HomeDashboard } from './features/home/HomeDashboard';
import { TopologyView } from './features/topology/TopologyView';
import { SecurityDashboard } from './features/security/SecurityDashboard';
import { AttackPathExplorer } from './features/attack-paths/AttackPathExplorer';
import { FindingsCenter } from './features/findings/FindingsCenter';
import { DetailedRemediationView } from './features/remediation/DetailedRemediationView';
import { ResilienceView } from './features/resilience/ResilienceView';
import { ComparisonView } from './features/comparison/ComparisonView';
import { ReportGenerationView } from './features/reports/ReportGenerationView';
import { UploadModals } from './components/UploadModals';
import { apiClient } from './api/client';
import { Project, AnalysisRun, Finding } from './types';
import { LARGE_ENTERPRISE_CONFIGS } from './assets/largeEnterpriseConfigs';

export function App() {
  const [currentScreen, setCurrentScreen] = useState<NavScreen>('home');
  const [isProfessionalMode, setIsProfessionalMode] = useState<boolean>(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [currentRun, setCurrentRun] = useState<AnalysisRun | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Modals
  const [isUploadConfigsOpen, setIsUploadConfigsOpen] = useState(false);
  const [isUploadPktOpen, setIsUploadPktOpen] = useState(false);

  // Load projects on startup
  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    try {
      const projs = await apiClient.listProjects();
      setProjects(projs);
      if (projs.length > 0 && !currentProject) {
        selectProject(projs[0]);
      }
    } catch (err) {
      console.error('Failed to load projects', err);
    }
  };

  const selectProject = async (proj: Project) => {
    try {
      const fullProj = await apiClient.getProject(proj.id);
      setCurrentProject(fullProj);
      if (fullProj.runs && fullProj.runs.length > 0) {
        const latestRunId = fullProj.runs[0].id;
        const runData = await apiClient.getRun(latestRunId);
        setCurrentRun(runData);
        if (runData.findings && runData.findings.length > 0) {
          setSelectedFinding(runData.findings[0]);
        }
      } else {
        setCurrentRun(null);
        setSelectedFinding(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateNewProject = async () => {
    const name = window.prompt('Enter new network project name:', 'Campus_Core_Design');
    if (!name || !name.trim()) return;
    try {
      const res = await apiClient.createProject(name.trim());
      await loadProjects();
      const p = await apiClient.getProject(res.id);
      await selectProject(p);
      setIsUploadConfigsOpen(true);
    } catch (err: any) {
      alert(err.message || 'Failed to create project');
    }
  };

  const handleResetAllData = async () => {
    if (window.confirm('Are you sure you want to remove all network projects and analysis runs? This will reset NetSec Analyzer completely to 0.')) {
      try {
        await apiClient.resetAllData();
        setProjects([]);
        setCurrentProject(null);
        setCurrentRun(null);
        setSelectedFinding(null);
        setCurrentScreen('home');
      } catch (err: any) {
        alert(err.message || 'Failed to reset all data');
      }
    }
  };

  const handleTriggerAnalysis = async () => {
    if (!currentProject) {
      setIsUploadConfigsOpen(true);
      return;
    }
    setIsAnalyzing(true);
    try {
      const run = await apiClient.runAnalysis(currentProject.id);
      setCurrentRun(run);
      if (run.findings.length > 0) {
        setSelectedFinding(run.findings[0]);
      }
      loadProjects();
    } catch (err: any) {
      alert(err.message || 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Sample loader fixtures
  const handleLoadSample = async (type: 'vulnerable' | 'hardened' | 'large_enterprise') => {
    setIsAnalyzing(true);
    try {
      const projName =
        type === 'large_enterprise'
          ? 'Large_Enterprise_Campus (6 Devices)'
          : type === 'vulnerable'
          ? 'Office_Network_Branch (Vulnerable)'
          : 'Enterprise_Core (Hardened)';
      const proj = await apiClient.createProject(projName, 'Enterprise campus network design fixture');

      if (type === 'large_enterprise') {
        for (const cfg of LARGE_ENTERPRISE_CONFIGS) {
          await apiClient.pasteConfig(proj.id, cfg.filename, cfg.content);
        }
      } else if (type === 'vulnerable') {
        const r1Config = `hostname R1\nenable password cisco123\nno service password-encryption\ninterface GigabitEthernet0/0\n description WAN-Uplink\n ip address 203.0.113.2 255.255.255.252\n ip access-group 100 in\n no shutdown\ninterface GigabitEthernet0/1\n description LAN-VLAN10-20\n ip address 192.168.1.1 255.255.255.0\n no shutdown\ninterface GigabitEthernet0/2\n description LAN-VLAN30-Servers\n ip address 192.168.30.1 255.255.255.0\n no shutdown\nip route 0.0.0.0 0.0.0.0 203.0.113.1\naccess-list 100 permit ip any any\nline vty 0 4\n transport input telnet\n login\n`;
        const sw1Config = `hostname Switch1\nenable password switchcisco\nvlan 1\n name default\ninterface FastEthernet0/1\n switchport mode access\n switchport access vlan 1\n no shutdown\ninterface FastEthernet0/2\n switchport mode access\n switchport access vlan 1\n no shutdown\ninterface GigabitEthernet0/1\n switchport mode trunk\n no shutdown\nline vty 0 4\n transport input telnet\n login\n`;
        const sw2Config = `hostname Switch2\nenable password switchcisco\nvlan 30\n name ServerFarm\ninterface FastEthernet0/1\n switchport mode access\n switchport access vlan 30\n no shutdown\ninterface GigabitEthernet0/1\n switchport mode trunk\n no shutdown\nline vty 0 4\n transport input telnet\n login\n`;

        await apiClient.pasteConfig(proj.id, 'R1_BranchRouter.cfg', r1Config);
        await apiClient.pasteConfig(proj.id, 'Switch1_Access.cfg', sw1Config);
        await apiClient.pasteConfig(proj.id, 'Switch2_Core.cfg', sw2Config);
      } else {
        const r1Hardened = `hostname R1\nenable secret 9 $9$Kx8Z3q7Lp1mN.v$8xT8gY7o9P1aQ2c\nservice password-encryption\ninterface GigabitEthernet0/0\n description WAN-Uplink\n ip address 203.0.113.2 255.255.255.252\n ip access-group 100 in\n no shutdown\ninterface GigabitEthernet0/1\n description LAN-VLAN10-20\n ip address 192.168.1.1 255.255.255.0\n ip access-group 101 in\n no shutdown\nip route 0.0.0.0 0.0.0.0 203.0.113.1\naccess-list 100 permit tcp any host 203.0.113.2 eq 443\naccess-list 100 deny ip any any log\naccess-list 101 permit tcp 192.168.10.0 0.0.0.255 host 192.168.30.10 eq 443\naccess-list 101 deny ip any any log\nline vty 0 4\n transport input ssh\n login local\n`;
        const sw1Hardened = `hostname Switch1\nenable secret 9 $9$Lz9B4r8Mq2nO.w$9yU9hZ8p0Q2bR3d\nservice password-encryption\nvlan 10\n name UserData\ninterface FastEthernet0/1\n switchport mode access\n switchport access vlan 10\n no shutdown\ninterface GigabitEthernet0/1\n switchport mode trunk\n no shutdown\ninterface GigabitEthernet0/2\n switchport mode trunk\n no shutdown\nline vty 0 4\n transport input ssh\n login local\n`;

        await apiClient.pasteConfig(proj.id, 'R1_Hardened.cfg', r1Hardened);
        await apiClient.pasteConfig(proj.id, 'Switch1_Hardened.cfg', sw1Hardened);
      }

      // Run analysis
      const run = await apiClient.runAnalysis(proj.id);
      await loadProjects();
      const updatedProj = await apiClient.getProject(proj.id);
      setCurrentProject(updatedProj);
      setCurrentRun(run);
      if (run.findings.length > 0) {
        setSelectedFinding(run.findings[0]);
      }
      setCurrentScreen('security');
    } catch (err: any) {
      alert(err.message || 'Failed to load sample');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setCurrentScreen('remediation-detail');
  };

  const handleMarkFindingResolved = (findingId: string) => {
    if (!currentRun) return;
    const updated = {
      ...currentRun,
      findings: currentRun.findings.map((f) =>
        f.id === findingId ? { ...f, is_resolved: true } : f
      ),
    };
    setCurrentRun(updated);
    if (selectedFinding && selectedFinding.id === findingId) {
      setSelectedFinding({ ...selectedFinding, is_resolved: true });
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-50 text-slate-900">
      {/* Left Navigation Sidebar */}
      <Sidebar
        currentScreen={currentScreen}
        onSelectScreen={setCurrentScreen}
        isProfessionalMode={isProfessionalMode}
        onToggleMode={setIsProfessionalMode}
        activeProjectName={currentProject?.name}
        onResetAllData={handleResetAllData}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        {/* Top Header */}
        <TopHeader
          currentScreen={currentScreen}
          onSelectScreen={setCurrentScreen}
          projectName={currentProject?.name}
          isAnalyzing={isAnalyzing}
          onTriggerAnalysis={handleTriggerAnalysis}
          onOpenUploadModal={() => setIsUploadConfigsOpen(true)}
          onCreateNewProject={handleCreateNewProject}
        />

        {/* Dynamic Screen View */}
        <main className="flex-1 overflow-y-auto bg-slate-50">
          {currentScreen === 'home' && (
            <HomeDashboard
              currentProject={currentProject}
              currentRun={currentRun}
              projects={projects}
              onSelectProject={selectProject}
              onOpenUploadPkt={() => setIsUploadPktOpen(true)}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
              onCreateNewProject={handleCreateNewProject}
              onLoadSample={handleLoadSample}
              onNavigate={setCurrentScreen}
              onFileUploadSuccess={async (projectId: string) => {
                await loadProjects();
                if (projectId) {
                  const p = await apiClient.getProject(projectId);
                  await selectProject(p);
                }
              }}
            />
          )}

          {currentScreen === 'topology' && (
            <TopologyView
              topologyData={currentRun?.topology}
              run={currentRun || undefined}
              onLoadSample={handleLoadSample}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'security' && (
            <SecurityDashboard
              run={currentRun || undefined}
              onSelectFinding={handleSelectFinding}
              onNavigateToReports={() => setCurrentScreen('reports')}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'attack-path' && (
            <AttackPathExplorer
              run={currentRun || undefined}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'findings' && (
            <FindingsCenter
              run={currentRun || undefined}
              onSelectFinding={handleSelectFinding}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'remediation-detail' && (
            <DetailedRemediationView
              finding={selectedFinding}
              onBack={() => setCurrentScreen('findings')}
              isProfessionalMode={isProfessionalMode}
              onToggleMode={setIsProfessionalMode}
              onMarkResolved={handleMarkFindingResolved}
            />
          )}

          {currentScreen === 'resilience' && (
            <ResilienceView
              run={currentRun || undefined}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'comparison' && (
            <ComparisonView
              currentProject={currentProject}
              currentRun={currentRun}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}

          {currentScreen === 'reports' && (
            <ReportGenerationView
              currentProject={currentProject}
              currentRun={currentRun}
              onOpenUploadConfigs={() => setIsUploadConfigsOpen(true)}
            />
          )}
        </main>
      </div>

      {/* Upload Modals */}
      <UploadModals
        projectId={currentProject?.id || ''}
        isOpenConfigs={isUploadConfigsOpen}
        isOpenPkt={isUploadPktOpen}
        onClose={() => {
          setIsUploadConfigsOpen(false);
          setIsUploadPktOpen(false);
        }}
        onSuccess={async (createdId) => {
          await loadProjects();
          if (createdId) {
            try {
              const p = await apiClient.getProject(createdId);
              await selectProject(p);
            } catch (e) {
              console.error(e);
            }
          }
        }}
        onLoadSample={handleLoadSample}
      />
    </div>
  );
}

export default App;
