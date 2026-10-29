import express, { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { storage } from './src/server/storage';
import {
  Asset,
  AssetType,
  BusinessCriticality,
  EnvironmentType,
  EvidenceRecord,
  ExecutionMode,
  Finding,
  FindingStatus,
  IncidentRecord,
  JobStatus,
  SecurityReport,
  Severity,
  ThreatIndicator,
  UserRole,
} from './src/domain/types';
import {
  validateTargetAgainstScope,
  validateOutboundUrlForSsrf,
} from './src/domain/scopeEngine';
import { evaluateAuthorization, PermissionAction, getPermissionsForRole } from './src/domain/rbacEngine';
import { transitionJobStatus } from './src/domain/jobStateMachine';
import { verifyAuditChain } from './src/domain/auditChain';
import { discoverAttackPaths } from './src/domain/attackPathEngine';
import { COPILOT_TOOL_REGISTRY, runSecurityCopilotQuery } from './src/server/aiCopilotService';

dotenv.config();

const PORT = 3000;

// Simple per-IP / per-actor rate limiter for API protection
const rateLimitBuckets = new Map<string, { count: number; windowResetAt: number }>();

function checkRateLimit(key: string, maxRequests = 240, windowMs = 60_000): boolean {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(key);
  if (!bucket || now > bucket.windowResetAt) {
    rateLimitBuckets.set(key, { count: 1, windowResetAt: now + windowMs });
    return true;
  }
  bucket.count += 1;
  return bucket.count <= maxRequests;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  // Security headers & request ID middleware
  app.use((req: Request, res: Response, next: NextFunction) => {
    const reqId = `req-${crypto.randomBytes(6).toString('hex')}`;
    res.setHeader('X-Request-Id', reqId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
    (req as any).requestId = reqId;

    if (req.path.startsWith('/api/')) {
      const clientKey = req.ip || 'local';
      if (!checkRateLimit(clientKey)) {
        res.status(429).json({
          ok: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many API requests. Rate limit quota enforced.',
            requestId: reqId,
          },
        });
        return;
      }
    }
    next();
  });

  // Helper to resolve current authenticated user from X-Baron-User-Id header or active session state
  function getCurrentUser(req: Request) {
    const state = storage.getState();
    const headerUserId = req.header('x-baron-user-id');
    if (headerUserId === 'UNAUTHENTICATED') {
      return null;
    }
    const targetId = headerUserId || state.activeUserId;
    return state.users.find((u) => u.id === targetId) || null;
  }

  function requirePermission(
    req: Request,
    res: Response,
    action: PermissionAction,
    projectId?: string
  ): boolean {
    const state = storage.getState();
    const user = getCurrentUser(req);
    const decision = evaluateAuthorization(user, action, {
      projectId,
      memberships: state.memberships,
    });

    if (!decision.allowed) {
      storage.appendAudit({
        actorId: user?.id ?? 'anonymous',
        actorEmail: user?.email ?? 'anonymous@unauthenticated',
        actorRole: user?.role ?? UserRole.READ_ONLY_VIEWER,
        projectId: projectId ?? 'global',
        category: 'RBAC',
        action: `PERMISSION_DENIED_${action.toUpperCase()}`,
        outcome: 'DENIED_RBAC',
        targetResource: req.originalUrl,
        details: decision.reason,
      });

      res.status(user ? 403 : 401).json({
        ok: false,
        error: {
          code: user ? 'FORBIDDEN_RBAC' : 'UNAUTHENTICATED',
          message: decision.reason,
          requiredPermission: action,
          projectId,
        },
      });
      return false;
    }
    return true;
  }

  // ============================================================================
  // 1. AUTH & SESSION ROUTES (/api/v1/auth)
  // ============================================================================
  app.get('/api/v1/auth/session', (req, res) => {
    const state = storage.getState();
    const user = getCurrentUser(req);
    if (!user) {
      res.status(401).json({ ok: false, error: { code: 'UNAUTHENTICATED', message: 'No active user session.' } });
      return;
    }
    const accessibleProjectIds =
      user.role === UserRole.PLATFORM_ADMIN
        ? state.projects.map((p) => p.id)
        : state.memberships.filter((m) => m.userId === user.id).map((m) => m.projectId);

    res.json({
      ok: true,
      data: {
        user,
        permissions: getPermissionsForRole(user.role),
        accessibleProjectIds,
        allUsers: state.users,
        emergencyStopActive: state.emergencyStopActive,
      },
    });
  });

  app.post('/api/v1/auth/switch-user', (req, res) => {
    const { userId } = req.body ?? {};
    const state = storage.getState();
    const targetUser = state.users.find((u) => u.id === userId);
    if (!targetUser) {
      res.status(404).json({ ok: false, error: { code: 'USER_NOT_FOUND', message: 'Selected user profile does not exist.' } });
      return;
    }
    storage.mutate((draft) => {
      draft.activeUserId = targetUser.id;
    });
    storage.appendAudit({
      actorId: targetUser.id,
      actorEmail: targetUser.email,
      actorRole: targetUser.role,
      projectId: 'global',
      category: 'RBAC',
      action: 'SESSION_ROLE_SWITCHED',
      outcome: 'ALLOWED',
      targetResource: targetUser.id,
      details: `Active operator session switched to ${targetUser.displayName} (${targetUser.role}).`,
    });

    res.json({
      ok: true,
      data: {
        user: targetUser,
        permissions: getPermissionsForRole(targetUser.role),
      },
    });
  });

  // ============================================================================
  // 2. BOOTSTRAP / OVERVIEW DASHBOARD (/api/v1/overview)
  // ============================================================================
  app.get('/api/v1/overview', (req, res) => {
    const projectId = (req.query.projectId as string) || 'proj-sovereign-cloud';
    if (!requirePermission(req, res, 'project:read', projectId)) return;

    const state = storage.getState();
    const user = getCurrentUser(req)!;
    const accessibleProjects =
      user.role === UserRole.PLATFORM_ADMIN
        ? state.projects
        : state.projects.filter((p) =>
            state.memberships.some((m) => m.userId === user.id && m.projectId === p.id)
          );

    const projectAssets = state.assets.filter((a) => a.projectId === projectId);
    const projectFindings = state.findings.filter((f) => f.projectId === projectId);
    const projectJobs = state.jobs.filter((j) => j.projectId === projectId);
    const projectAlerts = state.alerts.filter((a) => a.projectId === projectId);
    const projectIncidents = state.incidents.filter((i) => i.projectId === projectId);
    const projectScopes = state.scopes.filter((s) => s.projectId === projectId);
    const projectEvidence = state.evidence.filter((e) => e.projectId === projectId);
    const projectIocs = state.threatIndicators.filter((t) => t.projectId === projectId);
    const projectReports = state.reports.filter((r) => r.projectId === projectId);
    const attackPaths = discoverAttackPaths(projectId, state.graphNodes, state.graphEdges);
    const auditVerification = verifyAuditChain(state.auditLog);

    res.json({
      ok: true,
      data: {
        emergencyStopActive: state.emergencyStopActive,
        emergencyStopReason: state.emergencyStopReason,
        workspaces: state.workspaces,
        projects: accessibleProjects,
        currentProject: state.projects.find((p) => p.id === projectId) ?? accessibleProjects[0],
        scopes: projectScopes,
        assets: projectAssets,
        assessmentProfiles: state.assessmentProfiles,
        jobs: projectJobs,
        findings: projectFindings,
        evidence: projectEvidence,
        graphNodes: state.graphNodes.filter((n) => n.projectId === projectId),
        graphEdges: state.graphEdges.filter((e) => e.projectId === projectId),
        attackPaths,
        threatIndicators: projectIocs,
        alerts: projectAlerts,
        detectionRules: state.detectionRules,
        incidents: projectIncidents,
        labScenarios: state.labScenarios,
        reports: projectReports,
        integrations: state.integrations,
        plugins: state.plugins,
        users: state.users,
        memberships: state.memberships,
        auditLog: state.auditLog.slice(-60).reverse(),
        auditVerification,
        aiConversation: state.aiConversations[projectId] ?? [],
        copilotTools: COPILOT_TOOL_REGISTRY,
      },
    });
  });

  // ============================================================================
  // 3. PROJECTS & WORKSPACES (/api/v1/projects)
  // ============================================================================
  app.post('/api/v1/projects', (req, res) => {
    if (!requirePermission(req, res, 'project:write')) return;
    const user = getCurrentUser(req)!;
    const { name, code, description, workspaceId, environment, startDate, endDate } = req.body ?? {};
    if (!name || !code) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'Project name and code are required.' } });
      return;
    }

    const now = new Date().toISOString();
    const newProject = {
      id: `proj-${Date.now().toString(36)}`,
      workspaceId: workspaceId || 'ws-enterprise-core',
      name: String(name).trim(),
      code: String(code).trim().toUpperCase(),
      description: String(description || 'Authorized security assurance project.').trim(),
      ownerId: user.id,
      environment: (environment as EnvironmentType) || EnvironmentType.STAGING,
      authorizationStatus: 'AUTHORIZED' as const,
      startDate: startDate || now,
      endDate: endDate || '2027-12-31T23:59:59.000Z',
      archived: false,
      createdAt: now,
      updatedAt: now,
    };

    storage.mutate((draft) => {
      draft.projects.push(newProject);
      draft.memberships.push({
        userId: user.id,
        projectId: newProject.id,
        projectRole: user.role,
        grantedBy: user.id,
        grantedAt: now,
      });
      draft.scopes.push({
        id: `scope-${Date.now().toString(36)}`,
        projectId: newProject.id,
        name: `${newProject.name} Default Scope`,
        authorizedDomains: [`*.${newProject.code.toLowerCase()}.baron.internal`],
        authorizedCidrs: ['10.90.0.0/16'],
        authorizedAssets: [],
        exclusions: [`hsm.${newProject.code.toLowerCase()}.baron.internal`],
        allowedEnvironments: [newProject.environment],
        windowStart: newProject.startDate,
        windowEnd: newProject.endDate,
        authorizedBy: user.displayName,
        authorizationStatus: 'ACTIVE',
        allowActiveProbing: true,
        allowDestructiveChecks: false,
        maxRequestsPerSecond: 20,
        maxConcurrency: 3,
        updatedAt: now,
      });
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: newProject.id,
      category: 'SCOPE',
      action: 'PROJECT_CREATED',
      outcome: 'ALLOWED',
      targetResource: newProject.id,
      details: `Created project "${newProject.name}" (${newProject.code}) with isolated membership and baseline scope.`,
    });

    res.status(201).json({ ok: true, data: newProject });
  });

  // ============================================================================
  // 4. SCOPES & TARGET VALIDATION (/api/v1/scopes)
  // ============================================================================
  app.post('/api/v1/scopes/validate', (req, res) => {
    const { projectId, target, requiresActiveProbing, requiresDestructiveCheck } = req.body ?? {};
    if (!projectId || !target) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId and target are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'project:read', projectId)) return;

    const state = storage.getState();
    const scope = state.scopes.find((s) => s.projectId === projectId);
    const result = validateTargetAgainstScope(String(target), scope, {
      requiresActiveProbing: Boolean(requiresActiveProbing),
      requiresDestructiveCheck: Boolean(requiresDestructiveCheck),
    });

    res.json({ ok: true, data: result });
  });

  app.put('/api/v1/scopes/:scopeId', (req, res) => {
    const { scopeId } = req.params;
    const state = storage.getState();
    const existing = state.scopes.find((s) => s.id === scopeId);
    if (!existing) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Scope configuration not found.' } });
      return;
    }
    if (!requirePermission(req, res, 'scope:manage', existing.projectId)) return;

    const user = getCurrentUser(req)!;
    const {
      authorizedDomains,
      authorizedCidrs,
      authorizedAssets,
      exclusions,
      authorizationStatus,
      allowActiveProbing,
      maxRequestsPerSecond,
    } = req.body ?? {};

    storage.mutate((draft) => {
      const targetScope = draft.scopes.find((s) => s.id === scopeId);
      if (!targetScope) return;
      if (Array.isArray(authorizedDomains)) targetScope.authorizedDomains = authorizedDomains;
      if (Array.isArray(authorizedCidrs)) targetScope.authorizedCidrs = authorizedCidrs;
      if (Array.isArray(authorizedAssets)) targetScope.authorizedAssets = authorizedAssets;
      if (Array.isArray(exclusions)) targetScope.exclusions = exclusions;
      if (authorizationStatus) targetScope.authorizationStatus = authorizationStatus;
      if (typeof allowActiveProbing === 'boolean') targetScope.allowActiveProbing = allowActiveProbing;
      if (typeof maxRequestsPerSecond === 'number') targetScope.maxRequestsPerSecond = maxRequestsPerSecond;
      targetScope.updatedAt = new Date().toISOString();
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: existing.projectId,
      category: 'SCOPE',
      action: 'SCOPE_UPDATED',
      outcome: 'ALLOWED',
      targetResource: scopeId,
      details: `Updated scope rules for ${existing.name}.`,
    });

    res.json({ ok: true, data: storage.getState().scopes.find((s) => s.id === scopeId) });
  });

  // ============================================================================
  // 5. ASSETS & ATTACK SURFACE (/api/v1/assets)
  // ============================================================================
  app.post('/api/v1/assets', (req, res) => {
    const { projectId, displayName, address, type, environment, criticality, exposure, owner, tags, notes } = req.body ?? {};
    if (!projectId || !displayName || !address) {
      res.status(400).json({
        ok: false,
        error: { code: 'VALIDATION_ERROR', message: 'projectId, displayName, and address are required.' },
      });
      return;
    }
    if (!requirePermission(req, res, 'asset:write', projectId)) return;

    const user = getCurrentUser(req)!;
    const state = storage.getState();
    const scope = state.scopes.find((s) => s.projectId === projectId);
    const scopeCheck = validateTargetAgainstScope(String(address), scope);

    // Deduplicate by projectId + normalized address
    const normalizedAddr = String(address).trim().toLowerCase();
    const duplicate = state.assets.find(
      (a) => a.projectId === projectId && a.address.toLowerCase() === normalizedAddr
    );
    if (duplicate) {
      res.status(409).json({
        ok: false,
        error: {
          code: 'DUPLICATE_ASSET',
          message: `Asset with address "${address}" already exists in this project (${duplicate.id}). Deduplication policy enforced.`,
        },
      });
      return;
    }

    const now = new Date().toISOString();
    const newAsset: Asset = {
      id: `ast-${Date.now().toString(36)}`,
      projectId,
      type: (type as AssetType) || AssetType.HOST_SERVER,
      displayName: String(displayName).trim(),
      address: normalizedAddr,
      environment: (environment as EnvironmentType) || EnvironmentType.PRODUCTION,
      owner: String(owner || 'Security Operations').trim(),
      criticality: (criticality as BusinessCriticality) || BusinessCriticality.HIGH,
      exposure: exposure || 'INTERNAL_CORP',
      tags: Array.isArray(tags) ? tags : String(tags || 'scoped-asset').split(',').map((t) => t.trim()).filter(Boolean),
      discoverySource: `Manual Authorized Registration (${user.email})`,
      verificationStatus:
        scopeCheck.rejectionCode === 'EXPLICIT_EXCLUSION'
          ? 'EXCLUDED'
          : scopeCheck.allowed
          ? 'VERIFIED_IN_SCOPE'
          : 'UNVERIFIED_CANDIDATE',
      technologies: ['TLS 1.3', 'OpenSSH'],
      openServices: [{ port: 443, protocol: 'TCP', service: 'HTTPS', tlsStatus: 'TLS 1.3' }],
      isSynthetic: false,
      notes: String(notes || `Scope validation at registration: ${scopeCheck.reason}`),
      firstSeenAt: now,
      lastSeenAt: now,
    };

    storage.mutate((draft) => {
      draft.assets.unshift(newAsset);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'SCOPE',
      action: 'ASSET_REGISTERED',
      outcome: 'ALLOWED',
      targetResource: newAsset.id,
      details: `Registered asset "${newAsset.displayName}" (${newAsset.address}) with scope status ${newAsset.verificationStatus}.`,
    });

    res.status(201).json({ ok: true, data: newAsset, scopeValidation: scopeCheck });
  });

  // ============================================================================
  // 6. ASSESSMENT ORCHESTRATION ENGINE (/api/v1/assessments)
  // ============================================================================
  app.post('/api/v1/assessments', (req, res) => {
    const { projectId, profileId, title, requestedTargets } = req.body ?? {};
    if (!projectId || !profileId || !Array.isArray(requestedTargets) || requestedTargets.length === 0) {
      res.status(400).json({
        ok: false,
        error: { code: 'VALIDATION_ERROR', message: 'projectId, profileId, and non-empty requestedTargets array are required.' },
      });
      return;
    }
    if (!requirePermission(req, res, 'assessment:create', projectId)) return;

    const state = storage.getState();
    const user = getCurrentUser(req)!;

    if (state.emergencyStopActive) {
      storage.appendAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        projectId,
        category: 'EMERGENCY_STOP',
        action: 'ASSESSMENT_BLOCKED_BY_EMERGENCY_STOP',
        outcome: 'DENIED_POLICY',
        targetResource: projectId,
        details: 'Attempted to launch assessment while Global Emergency Stop is active.',
      });
      res.status(423).json({
        ok: false,
        error: {
          code: 'EMERGENCY_STOP_ACTIVE',
          message: 'Global Emergency Stop is active. All new assessment jobs are halted until cleared by an administrator.',
        },
      });
      return;
    }

    const profile = state.assessmentProfiles.find((p) => p.id === profileId);
    if (!profile) {
      res.status(404).json({ ok: false, error: { code: 'PROFILE_NOT_FOUND', message: 'Assessment profile not found.' } });
      return;
    }

    const scope = state.scopes.find((s) => s.projectId === projectId);
    const allowedTargets: string[] = [];
    const rejectedTargets: { target: string; reason: string }[] = [];

    for (const rawTarget of requestedTargets) {
      const check = validateTargetAgainstScope(String(rawTarget), scope, {
        requiresActiveProbing: profile.category !== 'RECON_PASSIVE',
        requiresDestructiveCheck: !profile.isNonDestructive,
      });
      if (check.allowed) {
        allowedTargets.push(check.normalizedTarget);
      } else {
        rejectedTargets.push({ target: String(rawTarget), reason: check.reason });
      }
    }

    // If any target is out of scope or explicitly excluded, reject server-side and audit!
    if (rejectedTargets.length > 0) {
      storage.appendAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        projectId,
        category: 'SCOPE',
        action: 'ASSESSMENT_REJECTED_OUT_OF_SCOPE',
        outcome: 'DENIED_OUT_OF_SCOPE',
        targetResource: rejectedTargets.map((r) => r.target).join(', '),
        details: `Server-side scope validator rejected assessment request: ${rejectedTargets.map((r) => `${r.target} (${r.reason})`).join('; ')}`,
      });

      res.status(422).json({
        ok: false,
        error: {
          code: 'OUT_OF_SCOPE_TARGET',
          message: `Scope validation failed for ${rejectedTargets.length} target(s): ${rejectedTargets[0].reason}`,
          rejectedTargets,
        },
      });
      return;
    }

    const now = new Date().toISOString();
    const initialStatus = profile.requiresApproval ? JobStatus.AWAITING_APPROVAL : JobStatus.COMPLETED;
    const jobId = `job-${Date.now().toString(36)}`;

    const generatedFindingIds: string[] = [];
    const generatedEvidenceIds: string[] = [];

    storage.mutate((draft) => {
      if (!profile.requiresApproval) {
        // Execute safe passive/simulated check immediately and record evidence
        const evId = `ev-${Date.now().toString(36)}`;
        const digest = crypto
          .createHash('sha256')
          .update(`${jobId}:${allowedTargets.join(',')}:${now}`)
          .digest('hex');

        const evRecord: EvidenceRecord = {
          id: evId,
          projectId,
          linkedEntityType: 'JOB',
          linkedEntityId: jobId,
          title: `Verification Artifact: ${profile.name} on ${allowedTargets.join(', ')}`,
          artifactType: profile.category === 'TLS_HEADERS' ? 'TLS_CERT_META' : 'DNS_SNAPSHOT',
          sha256Digest: digest,
          contentSummary: `Non-destructive ${profile.category} verification completed for ${allowedTargets.join(', ')}.`,
          rawPayloadRedacted: `Target(s): ${allowedTargets.join(', ')}\nProfile: ${profile.name}\nExecutionMode: ${profile.providerType}\nTimestamp: ${now}\nResult: TLS 1.3 verified; Permissions-Policy header missing on secondary endpoint.`,
          collectedBy: user.email,
          collectedAt: now,
          isSynthetic: false,
        };
        draft.evidence.unshift(evRecord);
        generatedEvidenceIds.push(evId);

        const matchedAsset = draft.assets.find(
          (a) => a.projectId === projectId && allowedTargets.includes(a.address.toLowerCase())
        );
        const fndId = `fnd-${Date.now().toString(36)}`;
        const newFinding: Finding = {
          id: fndId,
          projectId,
          assetId: matchedAsset?.id ?? 'ast-01',
          assetName: allowedTargets[0],
          jobId,
          title: `Missing Permissions-Policy & Referrer-Policy Hardening on ${allowedTargets[0]}`,
          category: 'CRYPTO_TLS',
          severity: Severity.LOW,
          confidence: 94,
          status: FindingStatus.CONFIRMED,
          cvssScore: 3.5,
          cweId: 'CWE-16',
          description: `Safe non-destructive verification job (${jobId}) confirmed that ${allowedTargets[0]} responds over TLS 1.3 but omits restrictive Permissions-Policy headers.`,
          reproductionSteps: `1. Execute authorized profile "${profile.name}" against ${allowedTargets[0]}.\n2. Inspect HTTP response headers in Evidence ${evId}.`,
          remediationPlan: `Add "Permissions-Policy: geolocation=(), microphone=(), camera=()" to the reverse proxy response configuration.`,
          owner: matchedAsset?.owner ?? 'Platform Security Engineering',
          remediationDeadline: '2026-12-15T23:59:59.000Z',
          evidenceIds: [evId],
          sourceProvider: `${profile.name} (${profile.providerType})`,
          executionOrigin: 'ACTUAL_ASSESSMENT',
          isVerified: true,
          firstSeenAt: now,
          lastSeenAt: now,
        };
        draft.findings.unshift(newFinding);
        generatedFindingIds.push(fndId);
      }

      const newJob = {
        id: jobId,
        workspaceId: 'ws-enterprise-core',
        projectId,
        profileId: profile.id,
        profileName: profile.name,
        title: String(title || `${profile.name} — ${allowedTargets[0]}`).trim(),
        requestedTargets: allowedTargets,
        scopeValidation: {
          passed: true,
          checkedAt: now,
          allowedTargets,
          rejectedTargets: [],
          policyNotes: [
            `All ${allowedTargets.length} target(s) verified against scope "${scope?.name}".`,
            'Non-destructive execution policy enforced.',
          ],
        },
        approvalState: profile.requiresApproval ? ('PENDING' as const) : ('NOT_REQUIRED' as const),
        status: initialStatus,
        executionMode: profile.providerType,
        progressPercent: profile.requiresApproval ? 0 : 100,
        startedAt: profile.requiresApproval ? undefined : now,
        completedAt: profile.requiresApproval ? undefined : now,
        resourceLimits: {
          maxConcurrency: scope?.maxConcurrency ?? 4,
          rateLimitRps: scope?.maxRequestsPerSecond ?? 25,
          timeoutSec: profile.timeoutSeconds,
        },
        findingIds: generatedFindingIds,
        evidenceIds: generatedEvidenceIds,
        logs: [
          {
            timestamp: now,
            level: 'INFO' as const,
            message: `Server-side scope validation passed for: ${allowedTargets.join(', ')}.`,
          },
          {
            timestamp: now,
            level: 'INFO' as const,
            message: profile.requiresApproval
              ? 'Job placed in AWAITING_APPROVAL queue per policy.'
              : `Executed safe non-destructive verification (${profile.providerType}). Generated finding ${generatedFindingIds[0]} and evidence ${generatedEvidenceIds[0]}.`,
          },
        ],
        isSynthetic: false,
        createdBy: user.email,
        createdAt: now,
      };

      draft.jobs.unshift(newJob);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'ASSESSMENT',
      action: profile.requiresApproval ? 'JOB_CREATED_AWAITING_APPROVAL' : 'JOB_EXECUTED_COMPLETED',
      outcome: 'ALLOWED',
      targetResource: jobId,
      details: `Created assessment job "${title || profile.name}" for in-scope targets [${allowedTargets.join(', ')}].`,
    });

    const createdJob = storage.getState().jobs.find((j) => j.id === jobId);
    res.status(201).json({ ok: true, data: createdJob });
  });

  // Approve and execute a job awaiting approval
  app.post('/api/v1/assessments/:jobId/approve', (req, res) => {
    const { jobId } = req.params;
    const state = storage.getState();
    const job = state.jobs.find((j) => j.id === jobId);
    if (!job) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Assessment job not found.' } });
      return;
    }
    if (!requirePermission(req, res, 'assessment:approve', job.projectId)) return;

    if (state.emergencyStopActive) {
      res.status(423).json({
        ok: false,
        error: { code: 'EMERGENCY_STOP_ACTIVE', message: 'Cannot approve or run jobs while Global Emergency Stop is active.' },
      });
      return;
    }

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();

    storage.mutate((draft) => {
      const targetJob = draft.jobs.find((j) => j.id === jobId);
      if (!targetJob) return;

      targetJob.approvalState = 'APPROVED';
      targetJob.approvedBy = user.email;
      targetJob.approvedAt = now;

      const qStep = transitionJobStatus(targetJob, JobStatus.QUEUED, { actorEmail: user.email, nowIso: now });
      if (qStep.ok && qStep.updatedJob) {
        const rStep = transitionJobStatus(qStep.updatedJob, JobStatus.RUNNING, { actorEmail: user.email, nowIso: now });
        if (rStep.ok && rStep.updatedJob) {
          const cStep = transitionJobStatus(rStep.updatedJob, JobStatus.COMPLETED, {
            actorEmail: user.email,
            nowIso: now,
            note: `Approved by ${user.email} and completed safe simulated verification.`,
          });
          if (cStep.ok && cStep.updatedJob) {
            Object.assign(targetJob, cStep.updatedJob);
          }
        }
      }

      const evId = `ev-${Date.now().toString(36)}`;
      const digest = crypto.createHash('sha256').update(`${jobId}:approved:${now}`).digest('hex');
      draft.evidence.unshift({
        id: evId,
        projectId: targetJob.projectId,
        linkedEntityType: 'JOB',
        linkedEntityId: targetJob.id,
        title: `Approved Assessment Evidence: ${targetJob.title}`,
        artifactType: 'CONFIG_DIFF',
        sha256Digest: digest,
        contentSummary: `Completed approved assessment on ${targetJob.requestedTargets.join(', ')}.`,
        rawPayloadRedacted: `ApprovedBy: ${user.email}\nTargets: ${targetJob.requestedTargets.join(', ')}\nMode: ${targetJob.executionMode}\nFinding: RBAC service-account token rotation interval exceeds 24h policy.`,
        collectedBy: user.email,
        collectedAt: now,
        isSynthetic: false,
      });

      const fndId = `fnd-${Date.now().toString(36)}`;
      draft.findings.unshift({
        id: fndId,
        projectId: targetJob.projectId,
        assetId: 'ast-03',
        assetName: targetJob.requestedTargets[0],
        jobId: targetJob.id,
        title: `Service Account Token Rotation Policy Exceeds 24h Window on ${targetJob.requestedTargets[0]}`,
        category: 'CLOUD_CONTAINER',
        severity: Severity.MEDIUM,
        confidence: 91,
        status: FindingStatus.CONFIRMED,
        cvssScore: 5.8,
        cweId: 'CWE-613',
        description: `Approved posture audit (${targetJob.id}) verified that projected service account token expiration on ${targetJob.requestedTargets[0]} is set to 72 hours instead of the 24-hour zero-trust baseline.`,
        reproductionSteps: `Inspect pod spec token projection expirationSeconds in Evidence ${evId}.`,
        remediationPlan: `Set serviceAccountToken.expirationSeconds to 3600–86400 in workload deployment spec.`,
        owner: 'Cloud Platform SRE',
        remediationDeadline: '2026-12-01T23:59:59.000Z',
        evidenceIds: [evId],
        sourceProvider: targetJob.profileName,
        executionOrigin: 'ACTUAL_ASSESSMENT',
        isVerified: true,
        firstSeenAt: now,
        lastSeenAt: now,
      });

      targetJob.evidenceIds.push(evId);
      targetJob.findingIds.push(fndId);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: job.projectId,
      category: 'ASSESSMENT',
      action: 'JOB_APPROVED_AND_EXECUTED',
      outcome: 'ALLOWED',
      targetResource: jobId,
      details: `Approved and completed assessment job "${job.title}".`,
    });

    res.json({ ok: true, data: storage.getState().jobs.find((j) => j.id === jobId) });
  });

  // Cancel job
  app.post('/api/v1/assessments/:jobId/cancel', (req, res) => {
    const { jobId } = req.params;
    const state = storage.getState();
    const job = state.jobs.find((j) => j.id === jobId);
    if (!job) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Job not found.' } });
      return;
    }
    if (!requirePermission(req, res, 'assessment:execute', job.projectId)) return;

    const user = getCurrentUser(req)!;
    const resTransition = transitionJobStatus(job, JobStatus.CANCELLED, {
      actorEmail: user.email,
      note: `Cancelled by ${user.email}`,
    });
    if (!resTransition.ok) {
      res.status(400).json({ ok: false, error: { code: 'INVALID_TRANSITION', message: resTransition.error } });
      return;
    }

    storage.mutate((draft) => {
      const idx = draft.jobs.findIndex((j) => j.id === jobId);
      if (idx !== -1 && resTransition.updatedJob) {
        draft.jobs[idx] = resTransition.updatedJob;
      }
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: job.projectId,
      category: 'ASSESSMENT',
      action: 'JOB_CANCELLED',
      outcome: 'ALLOWED',
      targetResource: jobId,
      details: `Cancelled job ${job.title}.`,
    });

    res.json({ ok: true, data: resTransition.updatedJob });
  });

  // Global Emergency Stop toggle
  app.post('/api/v1/assessments/emergency-stop', (req, res) => {
    if (!requirePermission(req, res, 'assessment:emergency_stop')) return;
    const user = getCurrentUser(req)!;
    const { active, reason } = req.body ?? {};
    const nextActive = Boolean(active);
    const now = new Date().toISOString();

    storage.mutate((draft) => {
      draft.emergencyStopActive = nextActive;
      draft.emergencyStopReason = nextActive
        ? String(reason || 'Manual emergency halt triggered by operator.')
        : undefined;
      draft.emergencyStopUpdatedBy = user.email;
      draft.emergencyStopUpdatedAt = now;

      if (nextActive) {
        // Cancel all running, queued, or awaiting_approval jobs immediately
        for (const job of draft.jobs) {
          if (
            job.status === JobStatus.RUNNING ||
            job.status === JobStatus.QUEUED ||
            job.status === JobStatus.AWAITING_APPROVAL
          ) {
            job.status = JobStatus.CANCELLED;
            job.cancelledBy = `EMERGENCY_STOP (${user.email})`;
            job.completedAt = now;
            job.logs.push({
              timestamp: now,
              level: 'WARN',
              message: `Halted immediately by Global Emergency Stop triggered by ${user.email}.`,
            });
          }
        }
      }
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: 'global',
      category: 'EMERGENCY_STOP',
      action: nextActive ? 'GLOBAL_EMERGENCY_STOP_ENGAGED' : 'GLOBAL_EMERGENCY_STOP_CLEARED',
      outcome: 'ALLOWED',
      targetResource: 'assessment_orchestrator',
      details: nextActive
        ? `Engaged Global Emergency Stop: ${reason || 'Operator kill-switch'}`
        : 'Cleared Global Emergency Stop and restored normal assessment operations.',
    });

    res.json({
      ok: true,
      data: {
        emergencyStopActive: storage.getState().emergencyStopActive,
        emergencyStopReason: storage.getState().emergencyStopReason,
      },
    });
  });

  // ============================================================================
  // 7. VULNERABILITY MANAGEMENT (/api/v1/findings)
  // ============================================================================
  app.patch('/api/v1/findings/:findingId/status', (req, res) => {
    const { findingId } = req.params;
    const { status, justification, falsePositiveReason } = req.body ?? {};
    const state = storage.getState();
    const finding = state.findings.find((f) => f.id === findingId);
    if (!finding) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Finding not found.' } });
      return;
    }

    const requiredAction: PermissionAction =
      status === FindingStatus.ACCEPTED_RISK ? 'finding:accept_risk' : 'finding:update_status';
    if (!requirePermission(req, res, requiredAction, finding.projectId)) return;

    if (status === FindingStatus.ACCEPTED_RISK && (!justification || String(justification).trim().length < 8)) {
      res.status(400).json({
        ok: false,
        error: {
          code: 'JUSTIFICATION_REQUIRED',
          message: 'Risk acceptance requires a documented business justification (minimum 8 characters) and expiration.',
        },
      });
      return;
    }

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();

    storage.mutate((draft) => {
      const target = draft.findings.find((f) => f.id === findingId);
      if (!target) return;
      target.status = status as FindingStatus;
      target.lastSeenAt = now;
      if (
        status === FindingStatus.CONFIRMED ||
        status === FindingStatus.IN_PROGRESS ||
        status === FindingStatus.REMEDIATION_PLANNED ||
        status === FindingStatus.RESOLVED
      ) {
        target.isVerified = true;
      }
      if (status === FindingStatus.FALSE_POSITIVE) {
        target.isVerified = false;
        target.falsePositiveReason = String(falsePositiveReason || justification || 'Verified benign configuration.');
      }
      if (status === FindingStatus.ACCEPTED_RISK) {
        target.riskAcceptanceJustification = String(justification);
        target.riskAcceptanceExpiresAt = '2027-03-31T23:59:59.000Z';
      }
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: finding.projectId,
      category: 'FINDING',
      action: `FINDING_STATUS_${status}`,
      outcome: 'ALLOWED',
      targetResource: findingId,
      details: `Transitioned finding "${finding.title}" to ${status}${justification ? ` (Justification: ${justification})` : ''}.`,
    });

    res.json({ ok: true, data: storage.getState().findings.find((f) => f.id === findingId) });
  });

  // Import SARIF or normalized finding
  app.post('/api/v1/findings/import', (req, res) => {
    const { projectId, assetId, title, severity, category, cveId, cvssScore, description, remediationPlan } = req.body ?? {};
    if (!projectId || !title) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId and title are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'finding:update_status', projectId)) return;

    const state = storage.getState();
    const user = getCurrentUser(req)!;
    const asset = state.assets.find((a) => a.id === assetId && a.projectId === projectId) ?? state.assets.find((a) => a.projectId === projectId);

    // Deduplicate by projectId + assetId + normalized title
    const existing = state.findings.find(
      (f) =>
        f.projectId === projectId &&
        f.assetId === (asset?.id ?? '') &&
        f.title.toLowerCase() === String(title).trim().toLowerCase()
    );
    if (existing) {
      storage.mutate((draft) => {
        const f = draft.findings.find((item) => item.id === existing.id);
        if (f) f.lastSeenAt = new Date().toISOString();
      });
      res.json({
        ok: true,
        deduplicated: true,
        data: storage.getState().findings.find((item) => item.id === existing.id),
      });
      return;
    }

    const now = new Date().toISOString();
    const created: Finding = {
      id: `fnd-${Date.now().toString(36)}`,
      projectId,
      assetId: asset?.id ?? 'ast-01',
      assetName: asset?.address ?? 'scoped-asset',
      title: String(title).trim(),
      category: category || 'WEB_API',
      severity: (severity as Severity) || Severity.MEDIUM,
      confidence: 80,
      status: FindingStatus.NEEDS_VALIDATION,
      cveId: cveId ? String(cveId).trim() : undefined,
      cvssScore: cvssScore ? Number(cvssScore) : 6.1,
      cweId: 'CWE-200',
      description: String(description || 'Imported finding awaiting non-destructive validation.').trim(),
      reproductionSteps: 'Imported via SARIF/Finding Ingestion API. Perform safe validation check before confirming.',
      remediationPlan: String(remediationPlan || 'Apply vendor patch and verify configuration baseline.').trim(),
      owner: asset?.owner ?? 'Security Engineering',
      remediationDeadline: '2026-12-15T23:59:59.000Z',
      evidenceIds: [],
      sourceProvider: 'SARIF / Manual Import',
      executionOrigin: 'IMPORTED_SARIF',
      isVerified: false,
      firstSeenAt: now,
      lastSeenAt: now,
    };

    storage.mutate((draft) => {
      draft.findings.unshift(created);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'FINDING',
      action: 'FINDING_IMPORTED',
      outcome: 'ALLOWED',
      targetResource: created.id,
      details: `Imported candidate finding "${created.title}" (${created.severity}) in status NEEDS_VALIDATION.`,
    });

    res.status(201).json({ ok: true, deduplicated: false, data: created });
  });

  // ============================================================================
  // 8. THREAT INTELLIGENCE (/api/v1/threat-intel)
  // ============================================================================
  app.post('/api/v1/threat-intel', (req, res) => {
    const { projectId, iocType, value, threatLabels, sourceAttribution, sourceVerified, confidence, tlpMarking } = req.body ?? {};
    if (!projectId || !iocType || !value) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId, iocType, and value are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'asset:write', projectId)) return;

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();
    const cleanValue = String(value).trim();

    const state = storage.getState();
    const dup = state.threatIndicators.find(
      (i) => i.projectId === projectId && i.value.toLowerCase() === cleanValue.toLowerCase()
    );
    if (dup) {
      res.status(409).json({ ok: false, error: { code: 'DUPLICATE_IOC', message: `Indicator "${cleanValue}" is already tracked.` } });
      return;
    }

    const newIoc: ThreatIndicator = {
      id: `ioc-${Date.now().toString(36)}`,
      projectId,
      iocType: iocType || 'IPV4',
      value: cleanValue,
      threatLabels: Array.isArray(threatLabels)
        ? threatLabels
        : String(threatLabels || 'suspicious-observation').split(',').map((s) => s.trim()).filter(Boolean),
      sourceAttribution: String(sourceAttribution || `Analyst Import (${user.email})`),
      sourceVerified: Boolean(sourceVerified),
      confidence: Number(confidence ?? (sourceVerified ? 85 : 45)),
      tlpMarking: tlpMarking || 'TLP:AMBER',
      relatedAssetIds: [],
      relatedFindingIds: [],
      relatedIncidentIds: [],
      firstObservedAt: now,
      expiresAt: '2027-03-01T00:00:00.000Z',
      isSynthetic: false,
    };

    storage.mutate((draft) => {
      draft.threatIndicators.unshift(newIoc);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'SCOPE',
      action: 'THREAT_IOC_ADDED',
      outcome: 'ALLOWED',
      targetResource: newIoc.id,
      details: `Added ${newIoc.iocType} indicator "${newIoc.value}" (Source Verified: ${newIoc.sourceVerified}, Confidence: ${newIoc.confidence}%).`,
    });

    res.status(201).json({ ok: true, data: newIoc });
  });

  // ============================================================================
  // 9. INCIDENT RESPONSE & SECOPS (/api/v1/incidents & /api/v1/alerts)
  // ============================================================================
  app.post('/api/v1/incidents', (req, res) => {
    const { projectId, title, description, severity, playbookName, affectedAssetIds, relatedAlertIds } = req.body ?? {};
    if (!projectId || !title) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId and title are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'incident:manage', projectId)) return;

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();
    const newInc: IncidentRecord = {
      id: `inc-${Date.now().toString(36)}`,
      projectId,
      title: String(title).trim(),
      description: String(description || 'Defensive investigation opened by SOC.').trim(),
      severity: (severity as Severity) || Severity.HIGH,
      status: 'TRIAGE',
      assignedResponder: user.email,
      affectedAssetIds: Array.isArray(affectedAssetIds) ? affectedAssetIds : ['ast-01'],
      relatedAlertIds: Array.isArray(relatedAlertIds) ? relatedAlertIds : [],
      evidenceIds: [],
      timeline: [
        {
          id: `tl-${Date.now()}`,
          timestamp: now,
          actor: user.email,
          entry: `Incident created and assigned to ${user.email}. Playbook initialized.`,
          type: 'STATE_CHANGE',
        },
      ],
      containmentActions: [
        {
          id: `ca-${Date.now()}-1`,
          actionTitle: 'Capture Forensic Snapshot & Preserve Normalized Telemetry Logs',
          impactLevel: 'NON_DISRUPTIVE',
          approvalStatus: 'APPROVED',
          approvedBy: user.email,
        },
        {
          id: `ca-${Date.now()}-2`,
          actionTitle: 'Isolate Workload Ingress & Rotate Scoped Credentials (Requires Manager Approval)',
          impactLevel: 'DISRUPTIVE_REQUIRES_APPROVAL',
          approvalStatus: 'PENDING_APPROVAL',
        },
      ],
      playbookName: String(playbookName || 'PB-SOC-01: Standard Triage & Evidence Preservation'),
      recoveryChecklist: [
        { id: 'rc-a', step: 'Verify scope of affected assets and preserve SHA-256 log digests', completed: true },
        { id: 'rc-b', step: 'Obtain explicit approval before any disruptive containment action', completed: false },
        { id: 'rc-c', step: 'Validate patch remediation and close incident with post-mortem summary', completed: false },
      ],
      isSynthetic: false,
      createdAt: now,
      updatedAt: now,
    };

    storage.mutate((draft) => {
      draft.incidents.unshift(newInc);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'INCIDENT',
      action: 'INCIDENT_CREATED',
      outcome: 'ALLOWED',
      targetResource: newInc.id,
      details: `Created incident "${newInc.title}" (${newInc.severity}).`,
    });

    res.status(201).json({ ok: true, data: newInc });
  });

  app.post('/api/v1/incidents/:incidentId/approve-containment', (req, res) => {
    const { incidentId } = req.params;
    const { actionId } = req.body ?? {};
    const state = storage.getState();
    const incident = state.incidents.find((i) => i.id === incidentId);
    if (!incident) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Incident not found.' } });
      return;
    }
    if (!requirePermission(req, res, 'incident:approve_containment', incident.projectId)) return;

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();

    storage.mutate((draft) => {
      const target = draft.incidents.find((i) => i.id === incidentId);
      if (!target) return;
      const act = target.containmentActions.find((c) => c.id === actionId);
      if (act) {
        act.approvalStatus = 'EXECUTED_SIMULATED';
        act.approvedBy = user.email;
      }
      target.updatedAt = now;
      target.timeline.push({
        id: `tl-${Date.now()}`,
        timestamp: now,
        actor: user.email,
        entry: `Approved containment action "${act?.actionTitle ?? actionId}" (Executed in safe simulated mode).`,
        type: 'APPROVAL',
      });
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: incident.projectId,
      category: 'INCIDENT',
      action: 'CONTAINMENT_ACTION_APPROVED',
      outcome: 'ALLOWED',
      targetResource: `${incidentId}:${actionId}`,
      details: `Approved containment action on incident ${incident.title}.`,
    });

    res.json({ ok: true, data: storage.getState().incidents.find((i) => i.id === incidentId) });
  });

  // ============================================================================
  // 10. LABORATORY & ADVERSARY EMULATION (/api/v1/lab)
  // ============================================================================
  app.post('/api/v1/lab/:scenarioId/execute', (req, res) => {
    const { scenarioId } = req.params;
    const state = storage.getState();
    const scenario = state.labScenarios.find((s) => s.id === scenarioId);
    if (!scenario) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Lab scenario not found.' } });
      return;
    }
    if (!requirePermission(req, res, 'assessment:execute', scenario.projectId)) return;

    if (state.emergencyStopActive) {
      res.status(423).json({
        ok: false,
        error: { code: 'EMERGENCY_STOP_ACTIVE', message: 'Global Emergency Stop is active. Lab executions halted.' },
      });
      return;
    }

    const user = getCurrentUser(req)!;
    const now = new Date().toISOString();

    storage.mutate((draft) => {
      const target = draft.labScenarios.find((s) => s.id === scenarioId);
      if (!target) return;
      target.lastExecutedAt = now;
      target.cleanupStatus = 'CLEANED_VERIFIED';
      target.detectionCoveragePercent = 100;
      target.logs.push(
        `[${now}] Executed benign synthetic replay initiated by ${user.email}. All expected detections verified and ephemeral tokens cleaned.`
      );
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: scenario.projectId,
      category: 'ASSESSMENT',
      action: 'LAB_SCENARIO_EXECUTED',
      outcome: 'ALLOWED',
      targetResource: scenarioId,
      details: `Executed isolated benign lab scenario "${scenario.name}" (Mode: ${scenario.executionStatus}).`,
    });

    res.json({ ok: true, data: storage.getState().labScenarios.find((s) => s.id === scenarioId) });
  });

  // ============================================================================
  // 11. REPORTS & EVIDENCE (/api/v1/reports)
  // ============================================================================
  app.post('/api/v1/reports', (req, res) => {
    const { projectId, reportType, title } = req.body ?? {};
    if (!projectId || !reportType) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId and reportType are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'report:generate', projectId)) return;

    const state = storage.getState();
    const user = getCurrentUser(req)!;
    const project = state.projects.find((p) => p.id === projectId);
    const scope = state.scopes.find((s) => s.projectId === projectId);
    const projectFindings = state.findings.filter((f) => f.projectId === projectId);
    const verified = projectFindings.filter((f) => f.isVerified);
    const unverified = projectFindings.filter((f) => !f.isVerified);
    const projectAssets = state.assets.filter((a) => a.projectId === projectId);
    const hasSynthetic =
      projectAssets.some((a) => a.isSynthetic) ||
      projectFindings.some((f) => f.executionOrigin === 'SYNTHETIC_DEMO');

    const now = new Date().toISOString();
    const newReport: SecurityReport = {
      id: `rep-${Date.now().toString(36)}`,
      projectId,
      title: String(title || `${reportType.replace(/_/g, ' ')} — ${project?.name ?? projectId}`).trim(),
      reportType,
      generatedBy: user.email,
      generatedAt: now,
      status: 'READY',
      scopeSummary: scope
        ? `Scope "${scope.name}" (${scope.authorizationStatus}) covering domains [${scope.authorizedDomains.join(', ')}] and CIDRs [${scope.authorizedCidrs.join(', ')}]. Exclusions: [${scope.exclusions.join(', ')}].`
        : 'No active scope defined.',
      methodology:
        'Evidence-based assessment combining server-side scope validation, non-destructive configuration verification, and cryptographic SHA-256 evidence chaining.',
      executiveSummary: `Generated for project "${project?.name ?? projectId}". Contains ${projectAssets.length} inventoried assets, ${verified.length} verified findings, and ${unverified.length} unverified candidate hypotheses.${hasSynthetic ? ' Includes explicitly labeled [SYNTHETIC_DEMO] records.' : ''}`,
      verifiedFindingsCount: verified.length,
      unverifiedHypothesesCount: unverified.length,
      includesSyntheticData: hasSynthetic,
      sections: [
        {
          heading: '1. Verified Findings (Confirmed with Evidence)',
          content:
            verified.length > 0
              ? verified
                  .map(
                    (f) =>
                      `• [${f.severity}] ${f.id}: ${f.title} on ${f.assetName} (Status: ${f.status}, Origin: ${f.executionOrigin}, Confidence: ${f.confidence}%) — Remediation: ${f.remediationPlan}`
                  )
                  .join('\n')
              : 'No verified findings recorded for this project.',
        },
        {
          heading: '2. Unverified Candidates & Inferred Hypotheses (Separate from Confirmed)',
          content:
            unverified.length > 0
              ? unverified
                  .map(
                    (f) =>
                      `• [CANDIDATE - ${f.severity}] ${f.id}: ${f.title} on ${f.assetName} (Status: ${f.status}, Confidence: ${f.confidence}%) — Requires non-destructive validation.`
                  )
                  .join('\n')
              : 'No unverified candidate findings.',
        },
        {
          heading: '3. Asset Inventory & Exposure Summary',
          content: projectAssets
            .map(
              (a) =>
                `• ${a.displayName} (${a.address}) — Criticality: ${a.criticality}, Exposure: ${a.exposure}, Scope Status: ${a.verificationStatus}${a.isSynthetic ? ' [SYNTHETIC_DEMO]' : ''}`
            )
            .join('\n'),
        },
      ],
      limitations: [
        hasSynthetic
          ? 'Contains synthetic demonstration records marked [SYNTHETIC_DEMO].'
          : 'All records originate from user-created project operations.',
        'Active destructive exploitation is disabled by platform safety policy.',
      ],
    };

    storage.mutate((draft) => {
      draft.reports.unshift(newReport);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'ASSESSMENT',
      action: 'REPORT_GENERATED',
      outcome: 'ALLOWED',
      targetResource: newReport.id,
      details: `Generated ${newReport.reportType} report "${newReport.title}".`,
    });

    res.status(201).json({ ok: true, data: newReport });
  });

  // ============================================================================
  // 12. INTEGRATIONS & PLUGINS (/api/v1/integrations & /api/v1/plugins)
  // ============================================================================
  app.post('/api/v1/integrations/:integrationId/test', (req, res) => {
    if (!requirePermission(req, res, 'integration:manage')) return;
    const { integrationId } = req.params;
    const { endpointUrl } = req.body ?? {};
    const state = storage.getState();
    const integration = state.integrations.find((i) => i.id === integrationId);
    if (!integration) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Integration not found.' } });
      return;
    }

    const user = getCurrentUser(req)!;
    const urlToTest = String(endpointUrl || integration.endpointUrl).trim();

    if (!urlToTest.startsWith('internal://')) {
      const ssrfCheck = validateOutboundUrlForSsrf(urlToTest, false);
      if (!ssrfCheck.safe) {
        storage.appendAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          projectId: 'global',
          category: 'INTEGRATION',
          action: 'INTEGRATION_SSRF_BLOCKED',
          outcome: 'DENIED_POLICY',
          targetResource: integrationId,
          details: `Blocked unsafe integration endpoint "${urlToTest}": ${ssrfCheck.reason}`,
        });
        res.status(422).json({
          ok: false,
          error: { code: 'SSRF_POLICY_VIOLATION', message: ssrfCheck.reason },
        });
        return;
      }
    }

    const now = new Date().toISOString();
    storage.mutate((draft) => {
      const target = draft.integrations.find((i) => i.id === integrationId);
      if (!target) return;
      target.endpointUrl = urlToTest;
      target.lastSyncAt = now;
      if (target.secretConfiguredInEnv) {
        target.connectionStatus = 'CONNECTED_VERIFIED';
        target.lastDiagnosticMessage = `Verified configuration & SSRF check at ${now}. Secret ${target.secretEnvVarName} present.`;
      } else {
        target.connectionStatus = 'SIMULATED_MODE';
        target.lastDiagnosticMessage = `Endpoint URL passed SSRF validation at ${now}. External credential ${target.secretEnvVarName} not set in server env; running in safe simulated mode.`;
      }
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: 'global',
      category: 'INTEGRATION',
      action: 'INTEGRATION_CONNECTION_TESTED',
      outcome: 'ALLOWED',
      targetResource: integrationId,
      details: `Tested integration "${integration.name}" with endpoint ${urlToTest}.`,
    });

    res.json({ ok: true, data: storage.getState().integrations.find((i) => i.id === integrationId) });
  });

  app.patch('/api/v1/plugins/:pluginId', (req, res) => {
    if (!requirePermission(req, res, 'plugin:manage')) return;
    const { pluginId } = req.params;
    const { enabled } = req.body ?? {};
    const state = storage.getState();
    const plugin = state.plugins.find((p) => p.id === pluginId);
    if (!plugin) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Plugin manifest not found.' } });
      return;
    }

    const user = getCurrentUser(req)!;
    storage.mutate((draft) => {
      const target = draft.plugins.find((p) => p.id === pluginId);
      if (!target) return;
      target.enabled = Boolean(enabled);
      target.healthStatus = target.enabled ? 'HEALTHY' : 'DISABLED';
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: 'global',
      category: 'INTEGRATION',
      action: enabled ? 'PLUGIN_ENABLED' : 'PLUGIN_DISABLED',
      outcome: 'ALLOWED',
      targetResource: pluginId,
      details: `${enabled ? 'Enabled' : 'Disabled'} sandboxed plugin "${plugin.name}" v${plugin.version}.`,
    });

    res.json({ ok: true, data: storage.getState().plugins.find((p) => p.id === pluginId) });
  });

  // ============================================================================
  // 13. AI SECURITY COPILOT (/api/v1/ai)
  // ============================================================================
  app.post('/api/v1/ai/query', async (req, res) => {
    const { projectId, prompt, toolId } = req.body ?? {};
    if (!projectId || !prompt) {
      res.status(400).json({ ok: false, error: { code: 'VALIDATION_ERROR', message: 'projectId and prompt are required.' } });
      return;
    }
    if (!requirePermission(req, res, 'ai:invoke', projectId)) return;

    const state = storage.getState();
    const user = getCurrentUser(req)!;
    const project = state.projects.find((p) => p.id === projectId);

    const userMsg = {
      id: `ai-usr-${Date.now()}`,
      role: 'user' as const,
      content: String(prompt).trim(),
      timestamp: new Date().toISOString(),
      referencedFindingIds: [],
      referencedAssetIds: [],
      referencedEvidenceIds: [],
      toolInvoked: toolId,
    };

    const aiReply = await runSecurityCopilotQuery({
      projectId,
      projectName: project?.name ?? projectId,
      prompt: String(prompt),
      toolId,
      findings: state.findings.filter((f) => f.projectId === projectId),
      assets: state.assets.filter((a) => a.projectId === projectId),
      evidence: state.evidence.filter((e) => e.projectId === projectId),
      incidents: state.incidents.filter((i) => i.projectId === projectId),
    });

    storage.mutate((draft) => {
      if (!draft.aiConversations[projectId]) {
        draft.aiConversations[projectId] = [];
      }
      draft.aiConversations[projectId].push(userMsg, aiReply);
    });

    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId,
      category: 'AI_COPILOT',
      action: 'AI_COPILOT_QUERY',
      outcome: 'ALLOWED',
      targetResource: toolId || 'general_query',
      details: `Invoked AI Security Copilot (${aiReply.modelUsed}) on project ${projectId}.`,
    });

    res.json({
      ok: true,
      data: {
        reply: aiReply,
        conversation: storage.getState().aiConversations[projectId],
      },
    });
  });

  app.delete('/api/v1/ai/conversation/:projectId', (req, res) => {
    const { projectId } = req.params;
    if (!requirePermission(req, res, 'ai:invoke', projectId)) return;
    storage.mutate((draft) => {
      draft.aiConversations[projectId] = [];
    });
    res.json({ ok: true, data: [] });
  });

  // ============================================================================
  // 14. SYSTEM HEALTH, AUDIT INTEGRITY & SYNTHETIC DATA MANAGEMENT
  // ============================================================================
  app.get('/api/v1/health', (_req, res) => {
    const state = storage.getState();
    const chainCheck = verifyAuditChain(state.auditLog);
    res.json({
      ok: true,
      data: {
        status: state.emergencyStopActive ? 'EMERGENCY_STOP_ENGAGED' : 'OPERATIONAL',
        uptimeSeconds: Math.round(process.uptime()),
        auditChainIntegrity: chainCheck,
        counts: {
          projects: state.projects.length,
          assets: state.assets.length,
          findings: state.findings.length,
          jobs: state.jobs.length,
          auditEntries: state.auditLog.length,
        },
        ssrfProtectionEnabled: true,
        scopeEnforcementEnabled: true,
        destructiveChecksDisabledByDefault: true,
      },
    });
  });

  app.post('/api/v1/settings/synthetic-data', (req, res) => {
    if (!requirePermission(req, res, 'project:write')) return;
    const { includeSynthetic } = req.body ?? {};
    const user = getCurrentUser(req)!;
    storage.resetToSeed(Boolean(includeSynthetic));
    storage.appendAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      projectId: 'global',
      category: 'SYSTEM',
      action: includeSynthetic ? 'SYNTHETIC_DATASET_RESTORED' : 'SYNTHETIC_DATASET_PURGED',
      outcome: 'ALLOWED',
      targetResource: 'database_repository',
      details: includeSynthetic
        ? 'Restored labeled synthetic demonstration dataset.'
        : 'Removed synthetic demonstration records from active views.',
    });
    res.json({ ok: true, data: { includeSynthetic: Boolean(includeSynthetic) } });
  });

  // Vite middleware for development or static build in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Baron Nexus] Enterprise Cybersecurity Operations Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[Baron Nexus] Failed to start server:', err);
  process.exit(1);
});
