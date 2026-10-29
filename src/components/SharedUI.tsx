import React, { useState } from 'react';
import { AuthorizedScope, Severity } from '../domain/types';

export type NavSectionId =
  | 'overview'
  | 'copilot'
  | 'assets'
  | 'assessments'
  | 'vulnerabilities'
  | 'attack-paths'
  | 'threat-intel'
  | 'secops'
  | 'incidents'
  | 'cloud-container'
  | 'web-api'
  | 'laboratory'
  | 'reports'
  | 'integrations'
  | 'plugins'
  | 'team'
  | 'audit'
  | 'health'
  | 'settings';

export const NAVIGATION_SECTIONS: {
  id: NavSectionId;
  label: string;
  group: 'Core Operations' | 'Intelligence & Exposure' | 'Defense & Validation' | 'Governance & Platform';
  shortcut: string;
}[] = [
  { id: 'overview', label: 'Overview', group: 'Core Operations', shortcut: 'G O' },
  { id: 'copilot', label: 'AI Security Copilot', group: 'Core Operations', shortcut: 'G C' },
  { id: 'assets', label: 'Assets and Attack Surface', group: 'Core Operations', shortcut: 'G A' },
  { id: 'assessments', label: 'Assessments', group: 'Core Operations', shortcut: 'G J' },
  { id: 'vulnerabilities', label: 'Vulnerability Management', group: 'Core Operations', shortcut: 'G V' },
  { id: 'attack-paths', label: 'Attack Path Analysis', group: 'Intelligence & Exposure', shortcut: 'G P' },
  { id: 'threat-intel', label: 'Threat Intelligence', group: 'Intelligence & Exposure', shortcut: 'G T' },
  { id: 'secops', label: 'Security Operations', group: 'Intelligence & Exposure', shortcut: 'G S' },
  { id: 'incidents', label: 'Incident Response', group: 'Intelligence & Exposure', shortcut: 'G I' },
  { id: 'cloud-container', label: 'Cloud and Container Security', group: 'Defense & Validation', shortcut: 'G K' },
  { id: 'web-api', label: 'Web and API Security', group: 'Defense & Validation', shortcut: 'G W' },
  { id: 'laboratory', label: 'Laboratory and Emulation', group: 'Defense & Validation', shortcut: 'G L' },
  { id: 'reports', label: 'Reports and Evidence', group: 'Defense & Validation', shortcut: 'G R' },
  { id: 'integrations', label: 'Integrations', group: 'Governance & Platform', shortcut: 'G N' },
  { id: 'plugins', label: 'Plugin Marketplace', group: 'Governance & Platform', shortcut: 'G M' },
  { id: 'team', label: 'Team and Access Control', group: 'Governance & Platform', shortcut: 'G U' },
  { id: 'audit', label: 'Audit Log', group: 'Governance & Platform', shortcut: 'G D' },
  { id: 'health', label: 'System Health', group: 'Governance & Platform', shortcut: 'G H' },
  { id: 'settings', label: 'Settings', group: 'Governance & Platform', shortcut: 'G E' },
];

/**
 * Clean unboxed severity text with semantic color & explicit label (Zero-Pill Discipline).
 */
export const SeverityLabel: React.FC<{ severity: Severity | string }> = ({ severity }) => {
  const colorMap: Record<string, string> = {
    CRITICAL: 'text-rose-400 font-semibold',
    HIGH: 'text-amber-400 font-semibold',
    MEDIUM: 'text-cyan-400 font-medium',
    LOW: 'text-slate-300 font-medium',
    INFO: 'text-slate-400',
  };
  return (
    <span className={`font-mono text-xs tracking-tight ${colorMap[severity] || 'text-slate-300'}`}>
      {severity}
    </span>
  );
};

export const VerificationLabel: React.FC<{ verified: boolean; origin?: string }> = ({
  verified,
  origin,
}) => {
  return (
    <span className="text-xs text-slate-400">
      <span className={verified ? 'text-emerald-400 font-medium' : 'text-amber-400 font-medium'}>
        {verified ? 'Verified' : 'Unverified Candidate'}
      </span>
      {origin && (
        <>
          <span className="mx-1.5 text-slate-600" aria-hidden="true">
            ·
          </span>
          <span className="font-mono text-[11px] text-slate-400">
            {origin === 'SYNTHETIC_DEMO' ? 'Synthetic Demo' : origin === 'ACTUAL_ASSESSMENT' ? 'Assessment Verified' : origin}
          </span>
        </>
      )}
    </span>
  );
};

export const SectionHeader: React.FC<{
  title: string;
  subtitle: string;
  actions?: React.ReactNode;
}> = ({ title, subtitle, actions }) => (
  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
    <div>
      <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-slate-100 text-balance">
        {title}
      </h1>
      <p className="mt-1 text-sm text-slate-400 max-w-3xl">{subtitle}</p>
    </div>
    {actions && <div className="flex items-center gap-2.5 shrink-0">{actions}</div>}
  </div>
);

export const MetricTile: React.FC<{
  label: string;
  value: string | number;
  meta: string;
  accent?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'violet';
  onClick?: () => void;
}> = ({ label, value, meta, accent = 'cyan', onClick }) => {
  const valueTone: Record<string, string> = {
    cyan: 'text-slate-100',
    emerald: 'text-emerald-400',
    amber: 'text-amber-400',
    rose: 'text-rose-400',
    violet: 'text-violet-400',
  };

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="text-left p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors focus-visible:outline-2 focus-visible:outline-cyan-400"
      >
        <div className="text-xs font-medium text-slate-400">{label}</div>
        <div className={`mt-1.5 text-2xl font-semibold font-mono tabular-nums ${valueTone[accent]}`}>
          {value}
        </div>
        <div className="mt-1 text-xs text-slate-400 truncate">{meta}</div>
      </button>
    );
  }

  return (
    <div className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg">
      <div className="text-xs font-medium text-slate-400">{label}</div>
      <div className={`mt-1.5 text-2xl font-semibold font-mono tabular-nums ${valueTone[accent]}`}>
        {value}
      </div>
      <div className="mt-1 text-xs text-slate-400 truncate">{meta}</div>
    </div>
  );
};

export const ScopeSummaryBanner: React.FC<{
  scope: AuthorizedScope | undefined;
  onOpenScopeModal: () => void;
}> = ({ scope, onOpenScopeModal }) => {
  if (!scope) {
    return (
      <div className="p-4 bg-rose-950/30 border border-rose-800/60 rounded-lg flex items-center justify-between gap-4">
        <div className="text-sm text-rose-200">
          <span className="font-semibold">No Active Scope Configured:</span> Active assessments are disabled by default until an authorized scope is established.
        </div>
        <button
          type="button"
          onClick={onOpenScopeModal}
          className="px-3 py-1.5 text-xs font-medium bg-rose-600 text-white rounded-md hover:bg-rose-500 whitespace-nowrap shrink-0"
        >
          Configure Scope
        </button>
      </div>
    );
  }

  return (
    <div className="px-4 py-3 bg-[#0F1523] border border-slate-800/80 rounded-lg flex flex-wrap items-center justify-between gap-4 text-xs">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-slate-300">
        <span className="font-medium text-slate-100">{scope.name}</span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className={scope.authorizationStatus === 'ACTIVE' ? 'text-emerald-400 font-medium' : 'text-amber-400 font-medium'}>
          Status: {scope.authorizationStatus}
        </span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className="font-mono text-slate-300">
          Domains: {scope.authorizedDomains.join(', ')}
        </span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className="font-mono text-slate-300">
          CIDRs: {scope.authorizedCidrs.join(', ')}
        </span>
        <span aria-hidden="true" className="text-slate-600">·</span>
        <span className="font-mono text-rose-300">
          Exclusions: {scope.exclusions.join(', ') || 'None'}
        </span>
      </div>
      <button
        type="button"
        onClick={onOpenScopeModal}
        className="px-3 py-1.5 text-xs font-medium text-cyan-300 bg-slate-800/90 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
      >
        Edit Scope & Exclusions
      </button>
    </div>
  );
};

export const ScopeEditModal: React.FC<{
  scope: AuthorizedScope | undefined;
  isOpen: boolean;
  onClose: () => void;
  onSave: (scopeId: string, updated: Partial<AuthorizedScope>) => Promise<void>;
}> = ({ scope, isOpen, onClose, onSave }) => {
  const [domainsText, setDomainsText] = useState(scope?.authorizedDomains.join(', ') || '');
  const [cidrsText, setCidrsText] = useState(scope?.authorizedCidrs.join(', ') || '');
  const [exclusionsText, setExclusionsText] = useState(scope?.exclusions.join(', ') || '');
  const [status, setStatus] = useState<AuthorizedScope['authorizationStatus']>(
    scope?.authorizationStatus || 'ACTIVE'
  );
  const [saving, setSaving] = useState(false);

  React.useEffect(() => {
    if (scope) {
      setDomainsText(scope.authorizedDomains.join(', '));
      setCidrsText(scope.authorizedCidrs.join(', '));
      setExclusionsText(scope.exclusions.join(', '));
      setStatus(scope.authorizationStatus);
    }
  }, [scope]);

  if (!isOpen || !scope) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(scope.id, {
        authorizedDomains: domainsText.split(',').map((s) => s.trim()).filter(Boolean),
        authorizedCidrs: cidrsText.split(',').map((s) => s.trim()).filter(Boolean),
        exclusions: exclusionsText.split(',').map((s) => s.trim()).filter(Boolean),
        authorizationStatus: status,
      });
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="scope-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
    >
      <div className="w-full max-w-xl bg-[#0F1523] border border-slate-700 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 id="scope-modal-title" className="text-lg font-semibold text-slate-100">
            Configure Authorized Scope & Exclusions
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200 rounded"
          >
            Close
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="scope-status-select" className="block text-xs font-medium text-slate-300 mb-1">
              Authorization Sign-Off State
            </label>
            <select
              id="scope-status-select"
              value={status}
              onChange={(e) => setStatus(e.target.value as AuthorizedScope['authorizationStatus'])}
              className="w-full px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded-md text-slate-100"
            >
              <option value="ACTIVE">ACTIVE (Assessments Permitted Within Scope)</option>
              <option value="PENDING_SIGNOFF">PENDING_SIGNOFF (Active Assessments Blocked)</option>
              <option value="EXPIRED">EXPIRED (Active Assessments Blocked)</option>
              <option value="REVOKED">REVOKED (Active Assessments Blocked)</option>
            </select>
          </div>

          <div>
            <label htmlFor="scope-domains-input" className="block text-xs font-medium text-slate-300 mb-1">
              Authorized Domains / Wildcards (Comma-separated)
            </label>
            <input
              id="scope-domains-input"
              type="text"
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono bg-[#090D16] border border-slate-700 rounded-md text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="scope-cidrs-input" className="block text-xs font-medium text-slate-300 mb-1">
              Authorized IPv4 CIDRs (Comma-separated)
            </label>
            <input
              id="scope-cidrs-input"
              type="text"
              value={cidrsText}
              onChange={(e) => setCidrsText(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono bg-[#090D16] border border-slate-700 rounded-md text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="scope-exclusions-input" className="block text-xs font-medium text-rose-300 mb-1">
              Explicit Exclusions — Always Blocked Server-Side (Comma-separated)
            </label>
            <input
              id="scope-exclusions-input"
              type="text"
              value={exclusionsText}
              onChange={(e) => setExclusionsText(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono bg-[#090D16] border border-rose-800/80 rounded-md text-slate-100"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-300 bg-slate-800 rounded-md hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
            >
              {saving ? 'Saving Policy...' : 'Save Scope Policy'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export const CommandPaletteModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onSelectSection: (section: NavSectionId) => void;
}> = ({ isOpen, onClose, onSelectSection }) => {
  const [query, setQuery] = useState('');
  if (!isOpen) return null;

  const filtered = NAVIGATION_SECTIONS.filter(
    (s) =>
      s.label.toLowerCase().includes(query.toLowerCase()) ||
      s.group.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command Palette"
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/75 pt-20 p-4"
    >
      <div className="w-full max-w-lg bg-[#0F1523] border border-slate-700 rounded-lg overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex items-center gap-2">
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to module, assessment workflow, or audit log..."
            aria-label="Search modules in Command Palette"
            className="w-full px-3 py-1.5 text-sm bg-[#090D16] border border-slate-700 rounded text-slate-100"
          />
          <button
            type="button"
            onClick={onClose}
            className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200"
          >
            Esc
          </button>
        </div>
        <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
          {filtered.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onSelectSection(item.id);
                onClose();
              }}
              className="w-full px-4 py-2.5 text-left flex items-center justify-between hover:bg-slate-800/70 transition-colors"
            >
              <div>
                <div className="text-sm font-medium text-slate-100">{item.label}</div>
                <div className="text-xs text-slate-400">{item.group}</div>
              </div>
              <span className="font-mono text-xs text-slate-400">{item.shortcut}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
