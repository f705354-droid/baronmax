import {
  AIMessage,
  AssessmentJob,
  AssessmentProfile,
  Asset,
  AuditLogEntry,
  AuthorizedScope,
  ComputedAttackPath,
  DetectionRule,
  EvidenceRecord,
  Finding,
  GraphEdge,
  GraphNode,
  IncidentRecord,
  IntegrationConfig,
  LabScenario,
  PluginManifest,
  Project,
  ProjectMembership,
  SecurityAlert,
  SecurityReport,
  ThreatIndicator,
  User,
  Workspace,
} from '../domain/types';
import { TargetValidationResult } from '../domain/scopeEngine';
import { CopilotToolDefinition } from '../server/aiCopilotService';
import {
  LanDiscoveredHost,
  LanHostAuditResult,
  LanModuleSelfAuditIssue,
  LanNicInfo,
  LanScanProfile,
  LanTrafficTelemetry,
} from '../domain/lanSecurityEngine';

export interface LanBootstrapPayload {
  hostname: string;
  kernel: string;
  privileges: {
    euid: number;
    isRoot: boolean;
    hasCapNetRaw: boolean;
    recommendedScanTechnique: string;
    privilegeNoticeAr: string;
  };
  interfaces: LanNicInfo[];
  activeSubnetCidr: string;
  discoveredHosts: LanDiscoveredHost[];
  latestHostAudit: LanHostAuditResult;
  traffic: LanTrafficTelemetry;
  consoleLogs: {
    id: string;
    timestamp: string;
    level: 'INFO' | 'WARN' | 'SECURITY' | 'SUCCESS';
    message: string;
  }[];
  selfAuditFixes?: LanModuleSelfAuditIssue[];
}

export interface OverviewPayload {
  emergencyStopActive: boolean;
  emergencyStopReason?: string;
  workspaces: Workspace[];
  projects: Project[];
  currentProject: Project;
  scopes: AuthorizedScope[];
  assets: Asset[];
  assessmentProfiles: AssessmentProfile[];
  jobs: AssessmentJob[];
  findings: Finding[];
  evidence: EvidenceRecord[];
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  attackPaths: ComputedAttackPath[];
  threatIndicators: ThreatIndicator[];
  alerts: SecurityAlert[];
  detectionRules: DetectionRule[];
  incidents: IncidentRecord[];
  labScenarios: LabScenario[];
  reports: SecurityReport[];
  integrations: IntegrationConfig[];
  plugins: PluginManifest[];
  users: User[];
  memberships: ProjectMembership[];
  auditLog: AuditLogEntry[];
  auditVerification: {
    valid: boolean;
    checkedCount: number;
    brokenAtSequence?: number;
    reason?: string;
  };
  aiConversation: AIMessage[];
  copilotTools: CopilotToolDefinition[];
}

export interface SessionPayload {
  user: User;
  permissions: string[];
  accessibleProjectIds: string[];
  allUsers: User[];
  emergencyStopActive: boolean;
}

async function requestJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
  });
  const body = await res.json().catch(() => ({ ok: false, error: { message: 'Invalid JSON response from server' } }));
  if (!res.ok || !body.ok) {
    const errMessage = body?.error?.message || `HTTP ${res.status} operation failed`;
    throw new Error(errMessage);
  }
  return body.data as T;
}

export const apiClient = {
  getSession: () => requestJson<SessionPayload>('/api/v1/auth/session'),

  switchUser: (userId: string) =>
    requestJson<{ user: User; permissions: string[] }>('/api/v1/auth/switch-user', {
      method: 'POST',
      body: JSON.stringify({ userId }),
    }),

  getOverview: (projectId: string) =>
    requestJson<OverviewPayload>(`/api/v1/overview?projectId=${encodeURIComponent(projectId)}`),

  createProject: (payload: {
    name: string;
    code: string;
    description: string;
    workspaceId?: string;
    environment?: string;
  }) =>
    requestJson<Project>('/api/v1/projects', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  validateTargetScope: (payload: {
    projectId: string;
    target: string;
    requiresActiveProbing?: boolean;
    requiresDestructiveCheck?: boolean;
  }) =>
    requestJson<TargetValidationResult>('/api/v1/scopes/validate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateScope: (scopeId: string, payload: Partial<AuthorizedScope>) =>
    requestJson<AuthorizedScope>(`/api/v1/scopes/${encodeURIComponent(scopeId)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  createAsset: (payload: {
    projectId: string;
    displayName: string;
    address: string;
    type: string;
    environment: string;
    criticality: string;
    exposure: string;
    owner: string;
    tags: string;
    notes?: string;
  }) =>
    requestJson<Asset>('/api/v1/assets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  createAssessmentJob: (payload: {
    projectId: string;
    profileId: string;
    title: string;
    requestedTargets: string[];
  }) =>
    requestJson<AssessmentJob>('/api/v1/assessments', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  approveAssessmentJob: (jobId: string) =>
    requestJson<AssessmentJob>(`/api/v1/assessments/${encodeURIComponent(jobId)}/approve`, {
      method: 'POST',
    }),

  cancelAssessmentJob: (jobId: string) =>
    requestJson<AssessmentJob>(`/api/v1/assessments/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST',
    }),

  setEmergencyStop: (active: boolean, reason?: string) =>
    requestJson<{ emergencyStopActive: boolean; emergencyStopReason?: string }>(
      '/api/v1/assessments/emergency-stop',
      {
        method: 'POST',
        body: JSON.stringify({ active, reason }),
      }
    ),

  updateFindingStatus: (findingId: string, status: string, justification?: string) =>
    requestJson<Finding>(`/api/v1/findings/${encodeURIComponent(findingId)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, justification }),
    }),

  importFinding: (payload: {
    projectId: string;
    assetId?: string;
    title: string;
    severity: string;
    category: string;
    cveId?: string;
    cvssScore?: number;
    description: string;
    remediationPlan: string;
  }) =>
    requestJson<Finding>('/api/v1/findings/import', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  addThreatIndicator: (payload: {
    projectId: string;
    iocType: string;
    value: string;
    threatLabels: string;
    sourceAttribution: string;
    sourceVerified: boolean;
    confidence: number;
    tlpMarking: string;
  }) =>
    requestJson<ThreatIndicator>('/api/v1/threat-intel', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  createIncident: (payload: {
    projectId: string;
    title: string;
    description: string;
    severity: string;
    playbookName: string;
  }) =>
    requestJson<IncidentRecord>('/api/v1/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  approveIncidentContainment: (incidentId: string, actionId: string) =>
    requestJson<IncidentRecord>(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/approve-containment`,
      {
        method: 'POST',
        body: JSON.stringify({ actionId }),
      }
    ),

  executeLabScenario: (scenarioId: string) =>
    requestJson<LabScenario>(`/api/v1/lab/${encodeURIComponent(scenarioId)}/execute`, {
      method: 'POST',
    }),

  generateReport: (payload: { projectId: string; reportType: string; title: string }) =>
    requestJson<SecurityReport>('/api/v1/reports', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  testIntegration: (integrationId: string, endpointUrl: string) =>
    requestJson<IntegrationConfig>(
      `/api/v1/integrations/${encodeURIComponent(integrationId)}/test`,
      {
        method: 'POST',
        body: JSON.stringify({ endpointUrl }),
      }
    ),

  togglePlugin: (pluginId: string, enabled: boolean) =>
    requestJson<PluginManifest>(`/api/v1/plugins/${encodeURIComponent(pluginId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),

  queryCopilot: (payload: { projectId: string; prompt: string; toolId?: string }) =>
    requestJson<{ reply: AIMessage; conversation: AIMessage[] }>('/api/v1/ai/query', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  clearCopilotConversation: (projectId: string) =>
    requestJson<AIMessage[]>(`/api/v1/ai/conversation/${encodeURIComponent(projectId)}`, {
      method: 'DELETE',
    }),

  toggleSyntheticData: (includeSynthetic: boolean) =>
    requestJson<{ includeSynthetic: boolean }>('/api/v1/settings/synthetic-data', {
      method: 'POST',
      body: JSON.stringify({ includeSynthetic }),
    }),

  getLanBootstrap: () => requestJson<LanBootstrapPayload>('/api/v1/lan/bootstrap'),

  discoverLanSubnet: (subnetCidr: string) =>
    requestJson<{
      activeSubnetCidr: string;
      discoveredHosts: LanDiscoveredHost[];
      latestHostAudit: LanHostAuditResult;
      consoleLogs: LanBootstrapPayload['consoleLogs'];
    }>('/api/v1/lan/discover', {
      method: 'POST',
      body: JSON.stringify({ subnetCidr }),
    }),

  auditLanHost: (targetIp: string, profile: LanScanProfile) =>
    requestJson<{
      latestHostAudit: LanHostAuditResult;
      consoleLogs: LanBootstrapPayload['consoleLogs'];
    }>('/api/v1/lan/audit-host', {
      method: 'POST',
      body: JSON.stringify({ targetIp, profile }),
    }),

  runLanDiagnosticTool: (payload: {
    toolType: 'REAL_LOCALHOST_AUDIT' | 'HTTP_HEADER_INSPECT' | 'KERNEL_SOCKET_ROUTE_DUMP' | 'ARP_SPOOF_DETECTOR_TEST';
    targetIp?: string;
    targetPort?: number;
  }) =>
    requestJson<{
      toolResult: {
        toolType: string;
        executedAt: string;
        summaryAr: string;
        rawOutput: string;
        structuredData?: any;
      };
      latestHostAudit: LanHostAuditResult;
      consoleLogs: LanBootstrapPayload['consoleLogs'];
    }>('/api/v1/lan/run-tool', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getKaliAgentBundle: () =>
    requestJson<{
      mainPy: string;
      requirementsTxt: string;
      setupKaliSh: string;
    }>('/api/v1/lan/kali-bundle'),
};

