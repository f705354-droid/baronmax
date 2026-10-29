import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthorizedScope,
  AssessmentJob,
  EnvironmentType,
  ExecutionMode,
  JobStatus,
  UserRole,
  BusinessCriticality,
  GraphNode,
  GraphEdge,
} from './types';
import {
  validateTargetAgainstScope,
  validateOutboundUrlForSsrf,
  isIpInCidr,
} from './scopeEngine';
import { evaluateAuthorization } from './rbacEngine';
import { transitionJobStatus } from './jobStateMachine';
import { createAuditEntry, verifyAuditChain } from './auditChain';
import { discoverAttackPaths } from './attackPathEngine';

const sampleScope: AuthorizedScope = {
  id: 'scope-1',
  projectId: 'proj-alpha',
  name: 'Core Banking Authorized Scope',
  authorizedDomains: ['*.baron-corp.internal', 'portal.baron-security.io'],
  authorizedCidrs: ['10.40.0.0/16'],
  authorizedAssets: ['vault-01.baron-corp.internal'],
  exclusions: ['payroll.baron-corp.internal', '10.40.99.0/24'],
  allowedEnvironments: [EnvironmentType.STAGING, EnvironmentType.PRODUCTION],
  windowStart: '2025-01-01T00:00:00.000Z',
  windowEnd: '2028-12-31T23:59:59.000Z',
  authorizedBy: 'ciso@baron-security.io',
  authorizationStatus: 'ACTIVE',
  allowActiveProbing: true,
  allowDestructiveChecks: false,
  maxRequestsPerSecond: 25,
  maxConcurrency: 4,
  updatedAt: '2026-10-01T00:00:00.000Z',
};

test('Scope validation: permits in-scope wildcard subdomain and CIDR IP', () => {
  const now = new Date('2026-10-29T12:00:00.000Z');
  const domainCheck = validateTargetAgainstScope('https://api.baron-corp.internal/v1/health', sampleScope, { now });
  assert.equal(domainCheck.allowed, true);
  assert.equal(domainCheck.normalizedTarget, 'api.baron-corp.internal');

  const cidrCheck = validateTargetAgainstScope('10.40.12.55', sampleScope, { now });
  assert.equal(cidrCheck.allowed, true);
  assert.equal(isIpInCidr('10.40.12.55', '10.40.0.0/16'), true);
});

test('Scope validation: rejects explicit exclusions even inside authorized wildcard/CIDR', () => {
  const now = new Date('2026-10-29T12:00:00.000Z');
  const excludedHost = validateTargetAgainstScope('payroll.baron-corp.internal', sampleScope, { now });
  assert.equal(excludedHost.allowed, false);
  assert.equal(excludedHost.rejectionCode, 'EXPLICIT_EXCLUSION');

  const excludedCidr = validateTargetAgainstScope('10.40.99.14', sampleScope, { now });
  assert.equal(excludedCidr.allowed, false);
  assert.equal(excludedCidr.rejectionCode, 'EXPLICIT_EXCLUSION');
});

test('Scope validation: rejects out-of-scope external targets and destructive checks', () => {
  const now = new Date('2026-10-29T12:00:00.000Z');
  const externalCheck = validateTargetAgainstScope('unapproved-thirdparty.com', sampleScope, { now });
  assert.equal(externalCheck.allowed, false);
  assert.equal(externalCheck.rejectionCode, 'OUT_OF_SCOPE');

  const destructiveCheck = validateTargetAgainstScope('api.baron-corp.internal', sampleScope, {
    now,
    requiresDestructiveCheck: true,
  });
  assert.equal(destructiveCheck.allowed, false);
  assert.equal(destructiveCheck.rejectionCode, 'DESTRUCTIVE_PROHIBITED');
});

test('SSRF protection: blocks cloud metadata, loopback, and private RFC1918 URLs', () => {
  const metadataCheck = validateOutboundUrlForSsrf('http://169.254.169.254/latest/meta-data/');
  assert.equal(metadataCheck.safe, false);

  const loopbackCheck = validateOutboundUrlForSsrf('http://localhost:8080/admin');
  assert.equal(loopbackCheck.safe, false);

  const rfc1918Check = validateOutboundUrlForSsrf('https://10.0.0.15/webhook', false);
  assert.equal(rfc1918Check.safe, false);

  const validExternalCheck = validateOutboundUrlForSsrf('https://misp.threat-partner.org/events');
  assert.equal(validExternalCheck.safe, true);
});

test('RBAC & Project Isolation: enforces least privilege and blocks cross-project access', () => {
  const viewerUser = {
    id: 'u-viewer',
    email: 'viewer@baron-security.io',
    displayName: 'Read Only Observer',
    role: UserRole.READ_ONLY_VIEWER,
    team: 'Compliance',
    mfaEnabled: true,
    activeSessionCount: 1,
    lastActiveAt: '2026-10-29T10:00:00.000Z',
  };

  const memberships = [
    {
      userId: 'u-viewer',
      projectId: 'proj-alpha',
      projectRole: UserRole.READ_ONLY_VIEWER,
      grantedBy: 'admin',
      grantedAt: '2026-10-01T00:00:00.000Z',
    },
  ];

  // Viewer can read in proj-alpha
  const readAllowed = evaluateAuthorization(viewerUser, 'project:read', {
    projectId: 'proj-alpha',
    memberships,
  });
  assert.equal(readAllowed.allowed, true);

  // Viewer cannot create assessments in proj-alpha
  const writeDenied = evaluateAuthorization(viewerUser, 'assessment:create', {
    projectId: 'proj-alpha',
    memberships,
  });
  assert.equal(writeDenied.allowed, false);

  // Viewer cannot read proj-beta (project isolation)
  const crossProjectDenied = evaluateAuthorization(viewerUser, 'project:read', {
    projectId: 'proj-beta',
    memberships,
  });
  assert.equal(crossProjectDenied.allowed, false);
});

test('Assessment Job State Machine: enforces valid transitions and Emergency Stop', () => {
  const baseJob: AssessmentJob = {
    id: 'job-101',
    workspaceId: 'ws-1',
    projectId: 'proj-alpha',
    profileId: 'prof-1',
    profileName: 'Safe TLS & Header Posture Check',
    title: 'TLS Validation Run',
    requestedTargets: ['api.baron-corp.internal'],
    scopeValidation: {
      passed: true,
      checkedAt: '2026-10-29T12:00:00.000Z',
      allowedTargets: ['api.baron-corp.internal'],
      rejectedTargets: [],
      policyNotes: [],
    },
    approvalState: 'APPROVED',
    status: JobStatus.SCOPE_VALIDATION,
    executionMode: ExecutionMode.SIMULATED,
    progressPercent: 10,
    resourceLimits: { maxConcurrency: 2, rateLimitRps: 10, timeoutSec: 60 },
    findingIds: [],
    evidenceIds: [],
    logs: [],
    isSynthetic: false,
    createdBy: 'analyst@baron-security.io',
    createdAt: '2026-10-29T12:00:00.000Z',
  };

  // Emergency stop blocks queuing
  const blockedByEmergency = transitionJobStatus(baseJob, JobStatus.QUEUED, {
    emergencyStopActive: true,
  });
  assert.equal(blockedByEmergency.ok, false);

  // Normal transition to QUEUED -> RUNNING -> COMPLETED
  const queued = transitionJobStatus(baseJob, JobStatus.QUEUED, { emergencyStopActive: false });
  assert.equal(queued.ok, true);
  assert.equal(queued.updatedJob?.status, JobStatus.QUEUED);

  const running = transitionJobStatus(queued.updatedJob!, JobStatus.RUNNING);
  assert.equal(running.ok, true);
  assert.equal(running.updatedJob?.status, JobStatus.RUNNING);

  const completed = transitionJobStatus(running.updatedJob!, JobStatus.COMPLETED);
  assert.equal(completed.ok, true);
  assert.equal(completed.updatedJob?.progressPercent, 100);
});

test('Audit Hash Chain: verifies integrity and detects tampering', () => {
  const entry1 = createAuditEntry(undefined, {
    id: 'aud-1',
    timestamp: '2026-10-29T12:00:00.000Z',
    actorId: 'u-1',
    actorEmail: 'admin@baron-security.io',
    actorRole: UserRole.PLATFORM_ADMIN,
    projectId: 'proj-alpha',
    category: 'SCOPE',
    action: 'SCOPE_APPROVED',
    outcome: 'ALLOWED',
    targetResource: 'scope-1',
    details: 'Approved scope window',
  });

  const entry2 = createAuditEntry(entry1, {
    id: 'aud-2',
    timestamp: '2026-10-29T12:05:00.000Z',
    actorId: 'u-1',
    actorEmail: 'admin@baron-security.io',
    actorRole: UserRole.PLATFORM_ADMIN,
    projectId: 'proj-alpha',
    category: 'ASSESSMENT',
    action: 'JOB_STARTED',
    outcome: 'ALLOWED',
    targetResource: 'job-101',
    details: 'Started safe TLS check',
  });

  const validResult = verifyAuditChain([entry1, entry2]);
  assert.equal(validResult.valid, true);
  assert.equal(validResult.checkedCount, 2);

  // Tamper with entry1 details
  const tampered = [{ ...entry1, details: 'Modified retroactively' }, entry2];
  const tamperedResult = verifyAuditChain(tampered);
  assert.equal(tamperedResult.valid, false);
  assert.equal(tamperedResult.brokenAtSequence, 1);
});

test('Attack Path Engine: discovers paths and distinguishes OBSERVED vs INFERRED_HYPOTHESIS', () => {
  const nodes: GraphNode[] = [
    {
      id: 'n1',
      projectId: 'proj-alpha',
      label: 'Edge API Gateway',
      nodeType: 'ASSET',
      criticality: BusinessCriticality.HIGH,
      exposure: 'INTERNET_FACING',
      privilegeLevel: 'SERVICE_ACCOUNT',
      verifiedFindingsCount: 2,
      metadata: {},
    },
    {
      id: 'n2',
      projectId: 'proj-alpha',
      label: 'Worker IAM Role',
      nodeType: 'IDENTITY',
      criticality: BusinessCriticality.HIGH,
      exposure: 'INTERNAL_CORP',
      privilegeLevel: 'ADMIN',
      verifiedFindingsCount: 1,
      metadata: {},
    },
    {
      id: 'n3',
      projectId: 'proj-alpha',
      label: 'Core Settlement Ledger DB',
      nodeType: 'ASSET',
      criticality: BusinessCriticality.MISSION_CRITICAL,
      exposure: 'ISOLATED_VPC',
      privilegeLevel: 'ROOT_CLUSTER',
      verifiedFindingsCount: 0,
      metadata: {},
    },
  ];

  const edges: GraphEdge[] = [
    {
      id: 'e1',
      projectId: 'proj-alpha',
      source: 'n1',
      target: 'n2',
      relationshipType: 'AUTHENTICATES_AS',
      derivation: 'OBSERVED',
      confidence: 95,
      evidenceRef: 'ev-1',
      observedAt: '2026-10-29T11:00:00.000Z',
    },
    {
      id: 'e2',
      projectId: 'proj-alpha',
      source: 'n2',
      target: 'n3',
      relationshipType: 'CAN_REACH_NETWORK',
      derivation: 'INFERRED_HYPOTHESIS',
      confidence: 75,
      evidenceRef: 'ev-2',
      observedAt: '2026-10-29T11:05:00.000Z',
    },
  ];

  const paths = discoverAttackPaths('proj-alpha', nodes, edges);
  assert.equal(paths.length, 1);
  assert.equal(paths[0].derivation, 'INFERRED_HYPOTHESIS');
  assert.equal(paths[0].chokePointNodeId, 'n2');
  assert.ok(paths[0].compositeRiskScore > 50);
});
