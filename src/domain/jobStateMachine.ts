import { AssessmentJob, JobStatus } from './types';

const VALID_TRANSITIONS: Record<JobStatus, JobStatus[]> = {
  [JobStatus.DRAFT]: [JobStatus.SCOPE_VALIDATION, JobStatus.CANCELLED],
  [JobStatus.SCOPE_VALIDATION]: [
    JobStatus.AWAITING_APPROVAL,
    JobStatus.QUEUED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
  ],
  [JobStatus.AWAITING_APPROVAL]: [JobStatus.QUEUED, JobStatus.CANCELLED, JobStatus.FAILED],
  [JobStatus.QUEUED]: [JobStatus.RUNNING, JobStatus.CANCELLED, JobStatus.FAILED],
  [JobStatus.RUNNING]: [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED],
  [JobStatus.COMPLETED]: [],
  [JobStatus.FAILED]: [],
  [JobStatus.CANCELLED]: [],
};

export function canTransitionJobStatus(from: JobStatus, to: JobStatus): boolean {
  return (VALID_TRANSITIONS[from] ?? []).includes(to);
}

export function transitionJobStatus(
  job: AssessmentJob,
  nextStatus: JobStatus,
  options: {
    emergencyStopActive?: boolean;
    actorEmail?: string;
    note?: string;
    nowIso?: string;
  } = {}
): { ok: boolean; updatedJob?: AssessmentJob; error?: string } {
  const nowIso = options.nowIso ?? new Date().toISOString();

  if (
    options.emergencyStopActive &&
    (nextStatus === JobStatus.QUEUED || nextStatus === JobStatus.RUNNING)
  ) {
    return {
      ok: false,
      error: 'Global Emergency Stop is currently active. No assessment jobs can be queued or started.',
    };
  }

  if (!canTransitionJobStatus(job.status, nextStatus)) {
    return {
      ok: false,
      error: `Invalid assessment job state transition from ${job.status} to ${nextStatus}.`,
    };
  }

  if (
    (nextStatus === JobStatus.QUEUED || nextStatus === JobStatus.RUNNING) &&
    !job.scopeValidation.passed
  ) {
    return {
      ok: false,
      error: 'Cannot queue or execute a job that has not passed server-side scope validation.',
    };
  }

  if (
    (nextStatus === JobStatus.QUEUED || nextStatus === JobStatus.RUNNING) &&
    job.approvalState === 'PENDING'
  ) {
    return {
      ok: false,
      error: 'Cannot queue or execute a job that is still awaiting human approval.',
    };
  }

  const updated: AssessmentJob = {
    ...job,
    status: nextStatus,
    logs: [
      ...job.logs,
      {
        timestamp: nowIso,
        level: nextStatus === JobStatus.FAILED || nextStatus === JobStatus.CANCELLED ? 'WARN' : 'INFO',
        message:
          options.note ??
          `Job transitioned from ${job.status} to ${nextStatus}${options.actorEmail ? ` by ${options.actorEmail}` : ''}.`,
      },
    ],
  };

  if (nextStatus === JobStatus.RUNNING) {
    updated.startedAt = nowIso;
    updated.progressPercent = 35;
  } else if (nextStatus === JobStatus.COMPLETED) {
    updated.completedAt = nowIso;
    updated.progressPercent = 100;
  } else if (nextStatus === JobStatus.CANCELLED) {
    updated.completedAt = nowIso;
    updated.cancelledBy = options.actorEmail ?? 'system';
  } else if (nextStatus === JobStatus.FAILED) {
    updated.completedAt = nowIso;
  }

  return { ok: true, updatedJob: updated };
}
