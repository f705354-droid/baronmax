import { AuthorizedScope, EnvironmentType } from './types';

export interface TargetValidationResult {
  allowed: boolean;
  target: string;
  normalizedTarget: string;
  matchedRule?: string;
  rejectionCode?:
    | 'SCOPE_INACTIVE'
    | 'WINDOW_EXPIRED'
    | 'EXPLICIT_EXCLUSION'
    | 'ENVIRONMENT_DISALLOWED'
    | 'DESTRUCTIVE_PROHIBITED'
    | 'ACTIVE_PROBING_DISABLED'
    | 'OUT_OF_SCOPE'
    | 'SSRF_BLOCKED_DESTINATION';
  reason: string;
}

/**
 * Checks if an IPv4 address belongs to a CIDR range (e.g. 10.20.0.0/16).
 */
export function isIpInCidr(ip: string, cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) return ip === cidr;
  const [rangeIp, prefixStr] = parts;
  const prefix = Number(prefixStr);
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipLong = ipv4ToLong(ip);
  const rangeLong = ipv4ToLong(rangeIp);
  if (ipLong === null || rangeLong === null) return false;

  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (ipLong & mask) === (rangeLong & mask);
}

export function ipv4ToLong(ip: string): number | null {
  const octets = ip.trim().split('.');
  if (octets.length !== 4) return null;
  let result = 0;
  for (const octet of octets) {
    if (!/^\d+$/.test(octet)) return null;
    const num = Number(octet);
    if (num < 0 || num > 255) return null;
    result = ((result << 8) | num) >>> 0;
  }
  return result >>> 0;
}

/**
 * Protects outbound integration calls against Server-Side Request Forgery (SSRF)
 * by blocking loopback, link-local, cloud metadata (169.254.169.254), and RFC1918
 * destinations unless explicitly permitted in an isolated lab test.
 */
export function validateOutboundUrlForSsrf(
  rawUrl: string,
  allowScopedInternalLab = false
): { safe: boolean; reason: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { safe: false, reason: 'Malformed URL format.' };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { safe: false, reason: `Disallowed URL protocol (${parsed.protocol}). Only HTTP/HTTPS permitted.` };
  }

  const host = parsed.hostname.toLowerCase();

  // Always block cloud metadata endpoints unconditionally
  if (
    host === '169.254.169.254' ||
    host === 'metadata.google.internal' ||
    host === 'metadata' ||
    host.startsWith('169.254.')
  ) {
    return {
      safe: false,
      reason: 'Blocked cloud instance metadata endpoint (169.254.169.254 / metadata.google.internal) to prevent SSRF.',
    };
  }

  // Block loopback & localhost
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '0.0.0.0' ||
    host === '[::1]' ||
    host.startsWith('127.')
  ) {
    return {
      safe: false,
      reason: 'Blocked loopback/localhost destination to prevent internal SSRF.',
    };
  }

  // Check private RFC1918 ranges if not in scoped internal lab
  if (!allowScopedInternalLab && ipv4ToLong(host) !== null) {
    if (
      isIpInCidr(host, '10.0.0.0/8') ||
      isIpInCidr(host, '172.16.0.0/12') ||
      isIpInCidr(host, '192.168.0.0/16') ||
      isIpInCidr(host, '100.64.0.0/10')
    ) {
      return {
        safe: false,
        reason: `Blocked RFC1918 private network address (${host}) for external integration webhook.`,
      };
    }
  }

  return { safe: true, reason: 'Outbound URL passed SSRF policy checks.' };
}

/**
 * Extracts normalized hostname or IP from a target string (domain, URL, IP, or host:port).
 */
export function normalizeTargetHost(rawTarget: string): string {
  const trimmed = rawTarget.trim().toLowerCase();
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try {
      const u = new URL(trimmed);
      return u.hostname.toLowerCase();
    } catch {
      return trimmed;
    }
  }
  // Strip path or port if not IPv6
  const withoutPath = trimmed.split('/')[0];
  const withoutPort = withoutPath.split(':')[0];
  return withoutPort;
}

function matchesDomainPattern(host: string, pattern: string): boolean {
  const cleanPattern = pattern.trim().toLowerCase();
  if (cleanPattern.startsWith('*.')) {
    const suffix = cleanPattern.slice(2);
    return host === suffix || host.endsWith(`.${suffix}`);
  }
  return host === cleanPattern;
}

/**
 * Server-side Scope Validation Engine that runs before every assessment operation.
 */
export function validateTargetAgainstScope(
  rawTarget: string,
  scope: AuthorizedScope | undefined,
  options: {
    now?: Date;
    environment?: EnvironmentType;
    requiresActiveProbing?: boolean;
    requiresDestructiveCheck?: boolean;
  } = {}
): TargetValidationResult {
  const normalizedTarget = normalizeTargetHost(rawTarget);

  if (!scope) {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'SCOPE_INACTIVE',
      reason: 'No authorized scope configuration exists for this project. Active assessments are disabled by default.',
    };
  }

  if (scope.authorizationStatus !== 'ACTIVE') {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'SCOPE_INACTIVE',
      reason: `Scope authorization status is ${scope.authorizationStatus}. Only ACTIVE signed-off scopes permit assessments.`,
    };
  }

  const checkTime = options.now ?? new Date();
  const start = new Date(scope.windowStart);
  const end = new Date(scope.windowEnd);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || checkTime < start || checkTime > end) {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'WINDOW_EXPIRED',
      reason: `Current time (${checkTime.toISOString()}) is outside the authorized testing window (${scope.windowStart} to ${scope.windowEnd}).`,
    };
  }

  if (options.requiresDestructiveCheck && !scope.allowDestructiveChecks) {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'DESTRUCTIVE_PROHIBITED',
      reason: 'Potentially destructive checks are strictly disabled by policy for this scope.',
    };
  }

  if (options.requiresActiveProbing && !scope.allowActiveProbing) {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'ACTIVE_PROBING_DISABLED',
      reason: 'Active network probing is disabled on this scope; only passive verification is permitted.',
    };
  }

  if (options.environment && !scope.allowedEnvironments.includes(options.environment)) {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'ENVIRONMENT_DISALLOWED',
      reason: `Environment ${options.environment} is not permitted in this scope (${scope.allowedEnvironments.join(', ')}).`,
    };
  }

  // Always block cloud metadata SSRF targets even if wildcard or broad CIDR is accidentally entered
  if (normalizedTarget === '169.254.169.254' || normalizedTarget === 'metadata.google.internal') {
    return {
      allowed: false,
      target: rawTarget,
      normalizedTarget,
      rejectionCode: 'SSRF_BLOCKED_DESTINATION',
      reason: 'Target matches restricted cloud metadata endpoint (169.254.169.254).',
    };
  }

  // 1. Check explicit exclusions first (Exclusions always override inclusions)
  for (const exclusion of scope.exclusions) {
    const cleanExcl = exclusion.trim().toLowerCase();
    if (!cleanExcl) continue;
    if (
      normalizedTarget === cleanExcl ||
      rawTarget.trim().toLowerCase() === cleanExcl ||
      matchesDomainPattern(normalizedTarget, cleanExcl) ||
      (ipv4ToLong(normalizedTarget) !== null && isIpInCidr(normalizedTarget, cleanExcl))
    ) {
      return {
        allowed: false,
        target: rawTarget,
        normalizedTarget,
        matchedRule: exclusion,
        rejectionCode: 'EXPLICIT_EXCLUSION',
        reason: `Target "${rawTarget}" matches explicit scope exclusion rule "${exclusion}".`,
      };
    }
  }

  // 2. Check explicit asset list
  for (const assetTarget of scope.authorizedAssets) {
    if (normalizeTargetHost(assetTarget) === normalizedTarget || assetTarget.toLowerCase() === rawTarget.trim().toLowerCase()) {
      return {
        allowed: true,
        target: rawTarget,
        normalizedTarget,
        matchedRule: `asset:${assetTarget}`,
        reason: `Authorized via explicit asset entry "${assetTarget}".`,
      };
    }
  }

  // 3. Check authorized domains / wildcard domains
  for (const domainPattern of scope.authorizedDomains) {
    if (matchesDomainPattern(normalizedTarget, domainPattern)) {
      return {
        allowed: true,
        target: rawTarget,
        normalizedTarget,
        matchedRule: `domain:${domainPattern}`,
        reason: `Authorized via domain scope rule "${domainPattern}".`,
      };
    }
  }

  // 4. Check authorized IPv4 CIDRs
  if (ipv4ToLong(normalizedTarget) !== null) {
    for (const cidr of scope.authorizedCidrs) {
      if (isIpInCidr(normalizedTarget, cidr)) {
        return {
          allowed: true,
          target: rawTarget,
          normalizedTarget,
          matchedRule: `cidr:${cidr}`,
          reason: `Authorized via IPv4 CIDR range "${cidr}".`,
        };
      }
    }
  }

  return {
    allowed: false,
    target: rawTarget,
    normalizedTarget,
    rejectionCode: 'OUT_OF_SCOPE',
    reason: `Target "${rawTarget}" does not match any authorized domain, CIDR range, or asset in scope "${scope.name}".`,
  };
}
