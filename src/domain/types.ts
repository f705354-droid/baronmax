export enum UserRole {
  PLATFORM_ADMIN = 'PLATFORM_ADMIN',
  SECURITY_MANAGER = 'SECURITY_MANAGER',
  SECURITY_ANALYST = 'SECURITY_ANALYST',
  PENETRATION_TESTER = 'PENETRATION_TESTER',
  INCIDENT_RESPONDER = 'INCIDENT_RESPONDER',
  AUDITOR = 'AUDITOR',
  READ_ONLY_VIEWER = 'READ_ONLY_VIEWER',
}

export enum EnvironmentType {
  PRODUCTION = 'PRODUCTION',
  STAGING = 'STAGING',
  DEVELOPMENT = 'DEVELOPMENT',
  ISOLATED_LAB = 'ISOLATED_LAB',
  CLOUD_INFRA = 'CLOUD_INFRA',
}

export enum BusinessCriticality {
  MISSION_CRITICAL = 'MISSION_CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

export enum FindingStatus {
  NEW = 'NEW',
  NEEDS_VALIDATION = 'NEEDS_VALIDATION',
  CONFIRMED = 'CONFIRMED',
  REMEDIATION_PLANNED = 'REMEDIATION_PLANNED',
  IN_PROGRESS = 'IN_PROGRESS',
  RETEST_REQUIRED = 'RETEST_REQUIRED',
  RESOLVED = 'RESOLVED',
  ACCEPTED_RISK = 'ACCEPTED_RISK',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
}

export enum JobStatus {
  DRAFT = 'DRAFT',
  SCOPE_VALIDATION = 'SCOPE_VALIDATION',
  AWAITING_APPROVAL = 'AWAITING_APPROVAL',
  QUEUED = 'QUEUED',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum AssetType {
  DOMAIN = 'DOMAIN',
  SUBDOMAIN = 'SUBDOMAIN',
  IP_RANGE = 'IP_RANGE',
  HOST_SERVER = 'HOST_SERVER',
  WEB_APP = 'WEB_APP',
  API_ENDPOINT = 'API_ENDPOINT',
  CLOUD_RESOURCE = 'CLOUD_RESOURCE',
  CONTAINER_K8S = 'CONTAINER_K8S',
  DATABASE = 'DATABASE',
  IDENTITY = 'IDENTITY',
  NETWORK_DEVICE = 'NETWORK_DEVICE',
  THIRD_PARTY_SCOPED = 'THIRD_PARTY_SCOPED',
}

export enum ExecutionMode {
  SIMULATED = 'SIMULATED',
  PASSIVE_INSPECTION = 'PASSIVE_INSPECTION',
  LOCAL_VERIFIED = 'LOCAL_VERIFIED',
  REMOTE_CONFIGURED = 'REMOTE_CONFIGURED',
  NOT_CONFIGURED = 'NOT_CONFIGURED',
}

export interface User {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
  team: string;
  mfaEnabled: boolean;
  activeSessionCount: number;
  lastActiveAt: string;
}

export interface ProjectMembership {
  userId: string;
  projectId: string;
  projectRole: UserRole;
  grantedBy: string;
  grantedAt: string;
}

export interface AuthorizedScope {
  id: string;
  projectId: string;
  name: string;
  authorizedDomains: string[];
  authorizedCidrs: string[];
  authorizedAssets: string[];
  exclusions: string[];
  allowedEnvironments: EnvironmentType[];
  windowStart: string;
  windowEnd: string;
  authorizedBy: string;
  authorizationStatus: 'ACTIVE' | 'PENDING_SIGNOFF' | 'EXPIRED' | 'REVOKED';
  allowActiveProbing: boolean;
  allowDestructiveChecks: boolean; // Must remain false unless isolated lab + explicit approval
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  updatedAt: string;
}

export interface Project {
  id: string;
  workspaceId: string;
  name: string;
  code: string;
  description: string;
  ownerId: string;
  environment: EnvironmentType;
  authorizationStatus: 'AUTHORIZED' | 'PENDING' | 'EXPIRED' | 'SUSPENDED';
  startDate: string;
  endDate: string;
  archived: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Workspace {
  id: string;
  name: string;
  organization: string;
  tier: string;
  createdAt: string;
}

export interface Asset {
  id: string;
  projectId: string;
  type: AssetType;
  displayName: string;
  address: string; // hostname, IP, CIDR, or cloud resource URI
  environment: EnvironmentType;
  owner: string;
  criticality: BusinessCriticality;
  exposure: 'INTERNET_FACING' | 'INTERNAL_CORP' | 'ISOLATED_VPC' | 'AIR_GAPPED';
  tags: string[];
  discoverySource: string;
  verificationStatus: 'VERIFIED_IN_SCOPE' | 'UNVERIFIED_CANDIDATE' | 'STALE' | 'EXCLUDED';
  technologies: string[];
  openServices: { port: number; protocol: string; service: string; tlsStatus?: string }[];
  isSynthetic: boolean;
  notes: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface AssessmentProfile {
  id: string;
  name: string;
  category: 'RECON_PASSIVE' | 'TLS_HEADERS' | 'VULN_VALIDATION' | 'CLOUD_POSTURE' | 'API_SCHEMA' | 'LAB_EMULATION';
  description: string;
  requiresApproval: boolean;
  isNonDestructive: boolean;
  providerType: ExecutionMode;
  timeoutSeconds: number;
}

export interface AssessmentJob {
  id: string;
  workspaceId: string;
  projectId: string;
  profileId: string;
  profileName: string;
  title: string;
  requestedTargets: string[];
  scopeValidation: {
    passed: boolean;
    checkedAt: string;
    allowedTargets: string[];
    rejectedTargets: { target: string; reason: string }[];
    policyNotes: string[];
  };
  approvalState: 'NOT_REQUIRED' | 'PENDING' | 'APPROVED' | 'REJECTED';
  approvedBy?: string;
  approvedAt?: string;
  status: JobStatus;
  executionMode: ExecutionMode;
  progressPercent: number;
  startedAt?: string;
  completedAt?: string;
  cancelledBy?: string;
  resourceLimits: {
    maxConcurrency: number;
    rateLimitRps: number;
    timeoutSec: number;
  };
  findingIds: string[];
  evidenceIds: string[];
  logs: { timestamp: string; level: 'INFO' | 'WARN' | 'ERROR'; message: string }[];
  errorClassification?: string;
  isSynthetic: boolean;
  createdBy: string;
  createdAt: string;
}

export interface Finding {
  id: string;
  projectId: string;
  assetId: string;
  assetName: string;
  jobId?: string;
  title: string;
  category: 'INFRASTRUCTURE' | 'WEB_API' | 'CLOUD_CONTAINER' | 'IAM_IDENTITY' | 'CRYPTO_TLS' | 'DEPENDENCY_SCA';
  severity: Severity;
  confidence: number; // 0 to 100
  status: FindingStatus;
  cveId?: string;
  cvssScore?: number;
  cweId?: string;
  description: string;
  reproductionSteps: string;
  remediationPlan: string;
  owner: string;
  remediationDeadline: string;
  riskAcceptanceJustification?: string;
  riskAcceptanceExpiresAt?: string;
  falsePositiveReason?: string;
  evidenceIds: string[];
  sourceProvider: string;
  executionOrigin: 'ACTUAL_ASSESSMENT' | 'SYNTHETIC_DEMO' | 'IMPORTED_SARIF';
  isVerified: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface EvidenceRecord {
  id: string;
  projectId: string;
  linkedEntityType: 'ASSET' | 'JOB' | 'FINDING' | 'INCIDENT';
  linkedEntityId: string;
  title: string;
  artifactType: 'HTTP_EXCHANGE' | 'TLS_CERT_META' | 'DNS_SNAPSHOT' | 'CONFIG_DIFF' | 'LOG_EXCERPT' | 'SARIF_REPORT';
  sha256Digest: string;
  contentSummary: string;
  rawPayloadRedacted: string;
  collectedBy: string;
  collectedAt: string;
  isSynthetic: boolean;
}

export interface GraphNode {
  id: string;
  projectId: string;
  label: string;
  nodeType: 'ASSET' | 'IDENTITY' | 'SERVICE' | 'PERMISSION' | 'FINDING' | 'CLOUD_RESOURCE' | 'SECURITY_CONTROL';
  criticality: BusinessCriticality;
  exposure: 'INTERNET_FACING' | 'INTERNAL_CORP' | 'ISOLATED_VPC';
  privilegeLevel: 'UNPRIVILEGED' | 'USER' | 'SERVICE_ACCOUNT' | 'ADMIN' | 'ROOT_CLUSTER';
  verifiedFindingsCount: number;
  metadata: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  projectId: string;
  source: string;
  target: string;
  relationshipType:
    | 'EXPOSES_SERVICE'
    | 'AUTHENTICATES_AS'
    | 'ASSUMES_ROLE'
    | 'HAS_VULNERABILITY'
    | 'CAN_REACH_NETWORK'
    | 'TRUSTS_IDENTITY'
    | 'MITIGATED_BY_CONTROL';
  derivation: 'OBSERVED' | 'INFERRED_HYPOTHESIS';
  confidence: number; // 0-100
  evidenceRef: string;
  observedAt: string;
}

export interface ComputedAttackPath {
  id: string;
  projectId: string;
  title: string;
  nodeSequence: string[];
  edgeSequence: string[];
  derivation: 'OBSERVED' | 'INFERRED_HYPOTHESIS';
  compositeRiskScore: number; // 0-100
  confidenceScore: number; // 0-100
  preconditions: string[];
  chokePointNodeId: string;
  recommendedControls: string[];
}

export interface ThreatIndicator {
  id: string;
  projectId: string;
  iocType: 'IPV4' | 'DOMAIN' | 'URL' | 'SHA256' | 'TLS_FINGERPRINT';
  value: string;
  threatLabels: string[];
  sourceAttribution: string;
  sourceVerified: boolean;
  confidence: number; // 0-100
  tlpMarking: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
  relatedAssetIds: string[];
  relatedFindingIds: string[];
  relatedIncidentIds: string[];
  firstObservedAt: string;
  expiresAt: string;
  isSynthetic: boolean;
}

export interface SecurityAlert {
  id: string;
  projectId: string;
  ruleId: string;
  ruleName: string;
  title: string;
  severity: Severity;
  confidence: number;
  status: 'NEW' | 'TRIAGING' | 'ESCALATED_TO_INCIDENT' | 'DISMISSED_BENIGN' | 'RESOLVED';
  sourceSystem: string;
  affectedAssetId: string;
  owner: string;
  matchExplanation: string;
  normalizedEventJson: string;
  investigationNotes: string[];
  linkedIncidentId?: string;
  isSynthetic: boolean;
  observedAt: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  version: string;
  severity: Severity;
  logSource: string;
  queryExpression: string;
  mitreTechnique: string;
  enabled: boolean;
  lastTestedAt: string;
  testPassStatus: 'PASS' | 'FAIL' | 'UNTESTED';
  rationale: string;
}

export interface IncidentRecord {
  id: string;
  projectId: string;
  title: string;
  description: string;
  severity: Severity;
  status: 'OPEN' | 'TRIAGE' | 'CONTAINMENT' | 'ERADICATION_RECOVERY' | 'POST_INCIDENT_REVIEW' | 'CLOSED';
  assignedResponder: string;
  affectedAssetIds: string[];
  relatedAlertIds: string[];
  evidenceIds: string[];
  timeline: { id: string; timestamp: string; actor: string; entry: string; type: 'NOTE' | 'STATE_CHANGE' | 'APPROVAL' }[];
  containmentActions: {
    id: string;
    actionTitle: string;
    impactLevel: 'NON_DISRUPTIVE' | 'DISRUPTIVE_REQUIRES_APPROVAL';
    approvalStatus: 'PENDING_APPROVAL' | 'APPROVED' | 'EXECUTED_SIMULATED' | 'REJECTED';
    approvedBy?: string;
  }[];
  playbookName: string;
  recoveryChecklist: { id: string; step: string; completed: boolean }[];
  closureSummary?: string;
  isSynthetic: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LabScenario {
  id: string;
  projectId: string;
  name: string;
  mitreMapping: string;
  labEnvironment: string;
  syntheticTarget: string;
  executionStatus: ExecutionMode;
  preconditions: string[];
  benignTestSteps: string[];
  expectedEvents: string[];
  expectedDetections: string[];
  observedOutcomes: string[];
  detectionCoveragePercent: number;
  cleanupStatus: 'CLEANED_VERIFIED' | 'PENDING_CLEANUP' | 'NOT_RUN';
  lastExecutedAt?: string;
  logs: string[];
}

export interface SecurityReport {
  id: string;
  projectId: string;
  title: string;
  reportType:
    | 'EXECUTIVE_SUMMARY'
    | 'TECHNICAL_ASSESSMENT'
    | 'VULNERABILITY_REGISTER'
    | 'ASSET_INVENTORY'
    | 'REMEDIATION_PLAN'
    | 'INCIDENT_REPORT'
    | 'ATTACK_PATH_ANALYSIS'
    | 'LAB_EXERCISE_REPORT'
    | 'AUDIT_COMPLIANCE';
  generatedBy: string;
  generatedAt: string;
  status: 'READY' | 'GENERATING' | 'FAILED';
  scopeSummary: string;
  methodology: string;
  executiveSummary: string;
  verifiedFindingsCount: number;
  unverifiedHypothesesCount: number;
  includesSyntheticData: boolean;
  sections: { heading: string; content: string }[];
  limitations: string[];
}

export interface IntegrationConfig {
  id: string;
  name: string;
  category: 'AI_ENGINE' | 'THREAT_INTEL' | 'VULN_SCANNER' | 'SIEM_LOGGING' | 'CLOUD_INVENTORY' | 'GIT_SCM' | 'NOTIFICATION';
  providerKey: string;
  enabled: boolean;
  connectionStatus: 'CONNECTED_VERIFIED' | 'SIMULATED_MODE' | 'NOT_CONFIGURED' | 'CONNECTION_ERROR';
  endpointUrl: string;
  secretEnvVarName: string;
  secretConfiguredInEnv: boolean;
  lastSyncAt?: string;
  lastDiagnosticMessage: string;
  supportedOperations: string[];
}

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  author: string;
  platformVersion: string;
  description: string;
  capabilities: string[];
  permissionsRequested: string[];
  requiredSecrets: string[];
  installed: boolean;
  enabled: boolean;
  isolationMode: 'WORKER_SANDBOX' | 'DECLARATIVE_SCHEMA_ONLY';
  executionLimits: { timeoutMs: number; memoryMb: number; rateLimitPerMin: number };
  healthStatus: 'HEALTHY' | 'DISABLED' | 'UNINSTALLED';
}

export interface AuditLogEntry {
  id: string;
  sequenceNumber: number;
  timestamp: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole;
  projectId: string;
  category: 'SCOPE' | 'ASSESSMENT' | 'FINDING' | 'INCIDENT' | 'RBAC' | 'AI_COPILOT' | 'INTEGRATION' | 'EMERGENCY_STOP' | 'SYSTEM';
  action: string;
  outcome: 'ALLOWED' | 'DENIED_OUT_OF_SCOPE' | 'DENIED_RBAC' | 'DENIED_POLICY' | 'ERROR';
  targetResource: string;
  details: string;
  prevHash: string;
  entryHash: string;
}

export interface AIMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  referencedFindingIds: string[];
  referencedAssetIds: string[];
  referencedEvidenceIds: string[];
  confidenceNote?: string;
  toolInvoked?: string;
  modelUsed?: string;
}
