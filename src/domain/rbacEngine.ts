import { ProjectMembership, User, UserRole } from './types';

export type PermissionAction =
  | 'project:read'
  | 'project:write'
  | 'project:delete'
  | 'scope:manage'
  | 'asset:read'
  | 'asset:write'
  | 'assessment:create'
  | 'assessment:approve'
  | 'assessment:execute'
  | 'assessment:emergency_stop'
  | 'finding:read'
  | 'finding:update_status'
  | 'finding:accept_risk'
  | 'incident:read'
  | 'incident:manage'
  | 'incident:approve_containment'
  | 'report:generate'
  | 'report:export'
  | 'integration:manage'
  | 'plugin:manage'
  | 'rbac:manage'
  | 'audit:read'
  | 'ai:invoke';

const ROLE_PERMISSIONS: Record<UserRole, PermissionAction[]> = {
  [UserRole.PLATFORM_ADMIN]: [
    'project:read',
    'project:write',
    'project:delete',
    'scope:manage',
    'asset:read',
    'asset:write',
    'assessment:create',
    'assessment:approve',
    'assessment:execute',
    'assessment:emergency_stop',
    'finding:read',
    'finding:update_status',
    'finding:accept_risk',
    'incident:read',
    'incident:manage',
    'incident:approve_containment',
    'report:generate',
    'report:export',
    'integration:manage',
    'plugin:manage',
    'rbac:manage',
    'audit:read',
    'ai:invoke',
  ],
  [UserRole.SECURITY_MANAGER]: [
    'project:read',
    'project:write',
    'scope:manage',
    'asset:read',
    'asset:write',
    'assessment:create',
    'assessment:approve',
    'assessment:execute',
    'assessment:emergency_stop',
    'finding:read',
    'finding:update_status',
    'finding:accept_risk',
    'incident:read',
    'incident:manage',
    'incident:approve_containment',
    'report:generate',
    'report:export',
    'integration:manage',
    'audit:read',
    'ai:invoke',
  ],
  [UserRole.SECURITY_ANALYST]: [
    'project:read',
    'asset:read',
    'asset:write',
    'assessment:create',
    'assessment:execute',
    'finding:read',
    'finding:update_status',
    'incident:read',
    'incident:manage',
    'report:generate',
    'report:export',
    'audit:read',
    'ai:invoke',
  ],
  [UserRole.PENETRATION_TESTER]: [
    'project:read',
    'asset:read',
    'asset:write',
    'assessment:create',
    'assessment:execute',
    'finding:read',
    'finding:update_status',
    'report:generate',
    'report:export',
    'ai:invoke',
  ],
  [UserRole.INCIDENT_RESPONDER]: [
    'project:read',
    'asset:read',
    'finding:read',
    'incident:read',
    'incident:manage',
    'report:generate',
    'report:export',
    'audit:read',
    'ai:invoke',
  ],
  [UserRole.AUDITOR]: [
    'project:read',
    'asset:read',
    'finding:read',
    'incident:read',
    'report:generate',
    'report:export',
    'audit:read',
    'ai:invoke',
  ],
  [UserRole.READ_ONLY_VIEWER]: [
    'project:read',
    'asset:read',
    'finding:read',
    'incident:read',
  ],
};

export interface AuthorizationDecision {
  allowed: boolean;
  effectiveRole?: UserRole;
  reason: string;
}

/**
 * Evaluates both role permissions and strict project-level isolation.
 * A project never inherits unrestricted permissions from another project.
 */
export function evaluateAuthorization(
  user: User | null | undefined,
  action: PermissionAction,
  options: {
    projectId?: string;
    memberships?: ProjectMembership[];
  } = {}
): AuthorizationDecision {
  if (!user) {
    return {
      allowed: false,
      reason: 'Unauthenticated request. Valid user session is required.',
    };
  }

  let effectiveRole = user.role;

  // Enforce project-level access isolation when a projectId is specified
  if (options.projectId && user.role !== UserRole.PLATFORM_ADMIN) {
    const membership = (options.memberships ?? []).find(
      (m) => m.userId === user.id && m.projectId === options.projectId
    );
    if (!membership) {
      return {
        allowed: false,
        reason: `User "${user.email}" (${user.role}) is not an authorized member of project "${options.projectId}". Project isolation enforced.`,
      };
    }
    effectiveRole = membership.projectRole;
  }

  const grantedActions = ROLE_PERMISSIONS[effectiveRole] ?? [];
  if (!grantedActions.includes(action)) {
    return {
      allowed: false,
      effectiveRole,
      reason: `Role "${effectiveRole}" does not grant permission "${action}". Least-privilege policy enforced.`,
    };
  }

  return {
    allowed: true,
    effectiveRole,
    reason: `Authorized via role "${effectiveRole}" for action "${action}".`,
  };
}

export function getPermissionsForRole(role: UserRole): PermissionAction[] {
  return ROLE_PERMISSIONS[role] ?? [];
}
