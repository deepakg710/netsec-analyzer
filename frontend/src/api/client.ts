import { Project, AnalysisRun, AttackPath, ResilienceResult, ComparisonResult } from '../types';

const API_BASE = '/api';

export const apiClient = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Backend health check failed');
    return res.json();
  },

  async listProjects(): Promise<Project[]> {
    const res = await fetch(`${API_BASE}/projects`);
    if (!res.ok) throw new Error('Failed to fetch projects');
    return res.json();
  },

  async createProject(name: string, description?: string): Promise<{ id: string; name: string; message: string }> {
    const res = await fetch(`${API_BASE}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create project' }));
      throw new Error(err.detail || 'Failed to create project');
    }
    return res.json();
  },

  async getProject(id: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects/${id}`);
    if (!res.ok) throw new Error('Project not found');
    return res.json();
  },

  async deleteProject(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/projects/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete project');
  },

  async uploadConfigs(projectId: string, files: File[]): Promise<any> {
    const formData = new FormData();
    files.forEach((f) => formData.append('files', f));
    const res = await fetch(`${API_BASE}/projects/${projectId}/upload-configs`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to upload configurations' }));
      throw new Error(err.detail || 'Failed to upload configurations');
    }
    return res.json();
  },

  async pasteConfig(projectId: string, filename: string, configText: string): Promise<any> {
    const res = await fetch(`${API_BASE}/projects/${projectId}/paste-config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, config_text: configText }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to ingest configuration snippet' }));
      throw new Error(err.detail || 'Failed to ingest configuration snippet');
    }
    return res.json();
  },

  async uploadPkt(projectId: string, file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/projects/${projectId}/upload-pkt`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to inspect Packet Tracer file' }));
      throw new Error(err.detail || 'Failed to inspect Packet Tracer file');
    }
    return res.json();
  },

  async runAnalysis(projectId: string): Promise<AnalysisRun> {
    const res = await fetch(`${API_BASE}/projects/${projectId}/analyze`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(err.detail || 'Analysis failed');
    }
    return res.json();
  },

  async getRun(runId: string): Promise<AnalysisRun> {
    const res = await fetch(`${API_BASE}/runs/${runId}`);
    if (!res.ok) throw new Error('Analysis run not found');
    return res.json();
  },

  async calculateAttackPath(
    runId: string,
    source: string,
    target: string,
    objective?: string,
    protocol: string = 'ip',
    dstPort?: number
  ): Promise<AttackPath> {
    const res = await fetch(`${API_BASE}/runs/${runId}/attack-path`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source,
        target,
        objective,
        protocol,
        dst_port: dstPort,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to calculate attack path' }));
      throw new Error(err.detail || 'Failed to calculate attack path');
    }
    return res.json();
  },

  async getResilience(runId: string): Promise<ResilienceResult> {
    const res = await fetch(`${API_BASE}/runs/${runId}/resilience`);
    if (!res.ok) throw new Error('Failed to fetch resilience metrics');
    return res.json();
  },

  async compareRuns(runAId: string, runBId: string): Promise<ComparisonResult> {
    const res = await fetch(`${API_BASE}/compare/${runAId}/${runBId}`);
    if (!res.ok) throw new Error('Failed to compare analysis runs');
    return res.json();
  },

  getReportDownloadUrl(runId: string, format: 'html' | 'pdf' | 'json'): string {
    return `${API_BASE}/runs/${runId}/report?format=${format}`;
  },

  async resetAllData(): Promise<{ message: string }> {
    const res = await fetch(`${API_BASE}/system/reset`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to reset all data');
    return res.json();
  },
};

