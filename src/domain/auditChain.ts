import crypto from 'node:crypto';
import { AuditLogEntry, UserRole } from './types';

export function computeAuditHash(payload: {
  sequenceNumber: number;
  timestamp: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole;
  projectId: string;
  category: AuditLogEntry['category'];
  action: string;
  outcome: AuditLogEntry['outcome'];
  targetResource: string;
  details: string;
  prevHash: string;
}): string {
  const canonical = [
    payload.sequenceNumber,
    payload.timestamp,
    payload.actorId,
    payload.actorEmail,
    payload.actorRole,
    payload.projectId,
    payload.category,
    payload.action,
    payload.outcome,
    payload.targetResource,
    payload.details,
    payload.prevHash,
  ].join('|');

  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function createAuditEntry(
  previousEntry: AuditLogEntry | undefined,
  params: {
    id: string;
    timestamp?: string;
    actorId: string;
    actorEmail: string;
    actorRole: UserRole;
    projectId: string;
    category: AuditLogEntry['category'];
    action: string;
    outcome: AuditLogEntry['outcome'];
    targetResource: string;
    details: string;
  }
): AuditLogEntry {
  const sequenceNumber = previousEntry ? previousEntry.sequenceNumber + 1 : 1;
  const prevHash = previousEntry ? previousEntry.entryHash : 'GENESIS_00000000000000000000000000000000';
  const timestamp = params.timestamp ?? new Date().toISOString();

  const entryHash = computeAuditHash({
    sequenceNumber,
    timestamp,
    actorId: params.actorId,
    actorEmail: params.actorEmail,
    actorRole: params.actorRole,
    projectId: params.projectId,
    category: params.category,
    action: params.action,
    outcome: params.outcome,
    targetResource: params.targetResource,
    details: params.details,
    prevHash,
  });

  return {
    id: params.id,
    sequenceNumber,
    timestamp,
    actorId: params.actorId,
    actorEmail: params.actorEmail,
    actorRole: params.actorRole,
    projectId: params.projectId,
    category: params.category,
    action: params.action,
    outcome: params.outcome,
    targetResource: params.targetResource,
    details: params.details,
    prevHash,
    entryHash,
  };
}

export function verifyAuditChain(entries: AuditLogEntry[]): {
  valid: boolean;
  checkedCount: number;
  brokenAtSequence?: number;
  reason?: string;
} {
  const sorted = [...entries].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  let expectedPrevHash = 'GENESIS_00000000000000000000000000000000';

  for (let i = 0; i < sorted.length; i++) {
    const item = sorted[i];
    if (item.sequenceNumber !== i + 1) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: item.sequenceNumber,
        reason: `Sequence gap detected at index ${i} (expected ${i + 1}, got ${item.sequenceNumber}).`,
      };
    }
    if (item.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: item.sequenceNumber,
        reason: `Previous hash mismatch at sequence ${item.sequenceNumber}.`,
      };
    }
    const recomputed = computeAuditHash(item);
    if (recomputed !== item.entryHash) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: item.sequenceNumber,
        reason: `Cryptographic SHA-256 digest mismatch at sequence ${item.sequenceNumber}.`,
      };
    }
    expectedPrevHash = item.entryHash;
  }

  return { valid: true, checkedCount: sorted.length };
}
