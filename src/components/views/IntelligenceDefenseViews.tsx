import React, { useState } from 'react';
import { apiClient, OverviewPayload } from '../../api/client';
import { Severity } from '../../domain/types';
import { SectionHeader, SeverityLabel, VerificationLabel } from '../SharedUI';

// ============================================================================
// 6. ATTACK PATH & GRAPH ANALYSIS VIEW
// ============================================================================
export const AttackPathAnalysisView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  const [derivationFilter, setDerivationFilter] = useState<'ALL' | 'OBSERVED' | 'INFERRED_HYPOTHESIS'>('ALL');
  const [selectedNodeId, setSelectedNodeId] = useState<string>(data.graphNodes[0]?.id || '');

  const filteredPaths = data.attackPaths.filter(
    (p) => derivationFilter === 'ALL' || p.derivation === derivationFilter
  );
  const selectedNode = data.graphNodes.find((n) => n.id === selectedNodeId) ?? data.graphNodes[0];

  // Deterministic coordinates for the interactive SVG attack graph with generous horizontal spacing
  const nodePositions: Record<string, { x: number; y: number }> = {
    'gn-api-gw': { x: 105, y: 75 },
    'gn-portal': { x: 105, y: 245 },
    'gn-k8s-worker': { x: 375, y: 75 },
    'gn-iam-sa': { x: 635, y: 165 },
    'gn-ledger-db': { x: 875, y: 165 },
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Attack-Path & Graph Relationship Analysis"
        subtitle="Typed, timestamped graph relationships distinguishing OBSERVED telemetry paths from INFERRED_HYPOTHESIS paths. Focuses on defensive choke-point remediation."
      />

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-1 p-1 bg-[#0F1523] border border-slate-800 rounded-lg">
          {(['ALL', 'OBSERVED', 'INFERRED_HYPOTHESIS'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setDerivationFilter(mode)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                derivationFilter === mode
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {mode === 'ALL'
                ? 'All Graph Paths'
                : mode === 'OBSERVED'
                ? 'Observed Paths (Evidence-Backed)'
                : 'Inferred Hypotheses'}
            </button>
          ))}
        </div>
        <div className="text-xs font-mono text-slate-400">
          Nodes: {data.graphNodes.length} · Typed Edges: {data.graphEdges.length} · Discovered Paths: {filteredPaths.length}
        </div>
      </div>

      {/* Interactive SVG Graph Explorer + Node Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 bg-[#0F1523] border border-slate-800/80 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 pb-3 border-b border-slate-800">
            <span>Interactive Topology & Trust Graph (Click any node to inspect)</span>
            <span className="font-mono">Solid Line = Observed · Dashed Line = Inferred Hypothesis</span>
          </div>
          <svg
            viewBox="0 0 980 320"
            className="w-full h-72 bg-[#090D16] rounded mt-3 border border-slate-800/60"
            role="img"
            aria-label="Attack path relationship graph"
          >
            {data.graphEdges.map((edge) => {
              const src = nodePositions[edge.source] || { x: 100, y: 100 };
              const dst = nodePositions[edge.target] || { x: 400, y: 150 };
              const isObserved = edge.derivation === 'OBSERVED';
              const midX = (src.x + dst.x) / 2;
              const midY = (src.y + dst.y) / 2;
              return (
                <g key={edge.id}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={isObserved ? '#22d3ee' : '#f59e0b'}
                    strokeWidth={2}
                    strokeDasharray={isObserved ? undefined : '6 4'}
                  />
                  <rect
                    x={midX - 68}
                    y={midY - 19}
                    width={136}
                    height={16}
                    rx={3}
                    fill="#090D16"
                    opacity={0.92}
                  />
                  <text
                    x={midX}
                    y={midY - 8}
                    textAnchor="middle"
                    fill={isObserved ? '#67e8f9' : '#fcd34d'}
                    fontSize="9.5"
                    fontFamily="monospace"
                  >
                    {edge.relationshipType} ({edge.confidence}%)
                  </text>
                </g>
              );
            })}

            {data.graphNodes.map((node) => {
              const pos = nodePositions[node.id] || { x: 200, y: 150 };
              const isSelected = selectedNode?.id === node.id;
              return (
                <g
                  key={node.id}
                  onClick={() => setSelectedNodeId(node.id)}
                  className="cursor-pointer"
                >
                  <rect
                    x={pos.x - 82}
                    y={pos.y - 25}
                    width={164}
                    height={50}
                    rx={6}
                    fill={isSelected ? '#164e63' : '#0F1523'}
                    stroke={
                      node.criticality === 'MISSION_CRITICAL'
                        ? '#f43f5e'
                        : isSelected
                        ? '#22d3ee'
                        : '#475569'
                    }
                    strokeWidth={isSelected ? 2.5 : 1.5}
                  />
                  <text
                    x={pos.x}
                    y={pos.y - 4}
                    textAnchor="middle"
                    fill="#f1f5f9"
                    fontSize="11"
                    fontWeight="600"
                  >
                    {node.label.slice(0, 23)}
                  </text>
                  <text
                    x={pos.x}
                    y={pos.y + 12}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                  >
                    {node.nodeType} · {node.privilegeLevel}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Node Details */}
        <div className="lg:col-span-4 bg-[#0F1523] border border-slate-800/80 rounded-lg p-5 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100">
            Selected Graph Node Inspector
          </h2>
          {selectedNode ? (
            <div className="space-y-2 text-xs">
              <div className="font-mono text-cyan-300 font-semibold">{selectedNode.label}</div>
              <div className="text-slate-400">
                Node ID: <span className="font-mono text-slate-200">{selectedNode.id}</span> · Type:{' '}
                <span className="font-mono text-slate-200">{selectedNode.nodeType}</span>
              </div>
              <div className="text-slate-400">
                Criticality: <span className="font-mono text-slate-200">{selectedNode.criticality}</span> · Exposure:{' '}
                <span className="font-mono text-slate-200">{selectedNode.exposure}</span>
              </div>
              <div className="text-slate-400">
                Privilege Level: <span className="font-mono text-amber-300">{selectedNode.privilegeLevel}</span>
              </div>
              <div className="text-slate-400">
                Verified Findings on Node:{' '}
                <span className="font-mono text-rose-400 font-semibold">
                  {selectedNode.verifiedFindingsCount}
                </span>
              </div>
              <div className="pt-2 border-t border-slate-800">
                <div className="font-semibold text-slate-300 mb-1">Node Metadata</div>
                {Object.entries(selectedNode.metadata).map(([k, v]) => (
                  <div key={k} className="font-mono text-[11px] text-slate-400">
                    {k}: {v}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-400">Select a node in the graph to inspect.</div>
          )}
        </div>
      </div>

      {/* Computed Attack Paths & Defensive Break Recommendations */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Computed Attack Paths & Choke-Point Remediation Controls
        </h2>
        {filteredPaths.map((path) => (
          <div
            key={path.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-semibold text-slate-100">{path.title}</div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span
                  className={
                    path.derivation === 'OBSERVED'
                      ? 'text-emerald-400 font-semibold'
                      : 'text-amber-400 font-semibold'
                  }
                >
                  {path.derivation === 'OBSERVED'
                    ? 'OBSERVED PATH'
                    : 'INFERRED HYPOTHESIS (UNVERIFIED)'}
                </span>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span className="text-rose-400 font-semibold">
                  Composite Risk: {path.compositeRiskScore}/100
                </span>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span className="text-slate-300">Confidence: {path.confidenceScore}%</span>
              </div>
            </div>
            <div className="text-xs text-slate-400">
              <span className="font-medium text-slate-200">Defensive Controls to Break Path:</span>{' '}
              {path.recommendedControls.join(' · ')}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 7. THREAT INTELLIGENCE & IOC MANAGEMENT VIEW
// ============================================================================
export const ThreatIntelligenceView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [iocType, setIocType] = useState('IPV4');
  const [value, setValue] = useState('');
  const [labels, setLabels] = useState('oauth-abuse, token-replay');
  const [sourceAttribution, setSourceAttribution] = useState('FS-ISAC Advisory Feed');
  const [sourceVerified, setSourceVerified] = useState(true);
  const [tlp, setTlp] = useState('TLP:AMBER');
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    try {
      await apiClient.addThreatIndicator({
        projectId: data.currentProject.id,
        iocType,
        value: value.trim(),
        threatLabels: labels,
        sourceAttribution,
        sourceVerified,
        confidence: sourceVerified ? 88 : 50,
        tlpMarking: tlp,
      });
      setValue('');
      setFeedback('Added indicator to Threat Intelligence registry.');
      await onRefresh();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Threat Intelligence & Indicator of Compromise (IOC) Registry"
        subtitle="Tracks IPv4, Domain, URL, SHA-256, and TLS fingerprint indicators with explicit source verification, confidence scores, and expiration policies. Unverified sources are never automatically labeled malicious."
      />

      {feedback && (
        <div className="p-3 bg-[#0F1523] border border-cyan-500/40 rounded text-xs text-cyan-200">
          {feedback}
        </div>
      )}

      <form
        onSubmit={handleAddIoc}
        className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4"
      >
        <h2 className="text-sm font-semibold text-slate-100">
          Ingest Threat Indicator (Sanitized & Deduplicated)
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div>
            <label htmlFor="ioc-type-select" className="block text-xs text-slate-400 mb-1">
              Indicator Type
            </label>
            <select
              id="ioc-type-select"
              value={iocType}
              onChange={(e) => setIocType(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              <option value="IPV4">IPV4</option>
              <option value="DOMAIN">DOMAIN</option>
              <option value="URL">URL</option>
              <option value="SHA256">SHA256</option>
              <option value="TLS_FINGERPRINT">TLS_FINGERPRINT</option>
            </select>
          </div>
          <div className="lg:col-span-2">
            <label htmlFor="ioc-value-input" className="block text-xs text-slate-400 mb-1">
              Indicator Value
            </label>
            <input
              id="ioc-value-input"
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="e.g. 203.0.113.42 or sha256 digest"
              className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="ioc-source-input" className="block text-xs text-slate-400 mb-1">
              Source Attribution
            </label>
            <input
              id="ioc-source-input"
              type="text"
              value={sourceAttribution}
              onChange={(e) => setSourceAttribution(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="ioc-tlp-select" className="block text-xs text-slate-400 mb-1">
              TLP Classification
            </label>
            <select
              id="ioc-tlp-select"
              value={tlp}
              onChange={(e) => setTlp(e.target.value)}
              className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              <option value="TLP:CLEAR">TLP:CLEAR</option>
              <option value="TLP:GREEN">TLP:GREEN</option>
              <option value="TLP:AMBER">TLP:AMBER</option>
              <option value="TLP:RED">TLP:RED</option>
            </select>
          </div>
        </div>
        <div className="flex items-center justify-between pt-2">
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={sourceVerified}
              onChange={(e) => setSourceVerified(e.target.checked)}
            />
            Source Attribution Cryptographically / Analyst Verified
          </label>
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
          >
            Add Threat Indicator
          </button>
        </div>
      </form>

      <div className="bg-[#0F1523] border border-slate-800/80 rounded-lg overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400">
              <th className="py-3 px-4">Type & Indicator Value</th>
              <th className="py-3 px-4">Source & Provenance</th>
              <th className="py-3 px-4">Confidence & TLP</th>
              <th className="py-3 px-4">Correlated Records</th>
              <th className="py-3 px-4">Expiration</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {data.threatIndicators.map((ioc) => (
              <tr key={ioc.id} className="hover:bg-slate-800/30">
                <td className="py-3 px-4">
                  <div className="font-mono text-cyan-300">{ioc.value}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {ioc.iocType} · {ioc.threatLabels.join(' · ')}
                  </div>
                </td>
                <td className="py-3 px-4">
                  <div className="text-slate-200">{ioc.sourceAttribution}</div>
                  <div
                    className={`font-mono text-[11px] ${
                      ioc.sourceVerified ? 'text-emerald-400' : 'text-amber-400'
                    }`}
                  >
                    {ioc.sourceVerified
                      ? 'Verified Feed Attribution'
                      : 'Unverified External Feed (Treat as Candidate)'}
                  </div>
                </td>
                <td className="py-3 px-4 font-mono">
                  <div className="text-slate-100">{ioc.confidence}% Confidence</div>
                  <div className="text-amber-300 text-[11px]">{ioc.tlpMarking}</div>
                </td>
                <td className="py-3 px-4 font-mono text-slate-400">
                  Assets: {ioc.relatedAssetIds.join(', ') || 'None'} · Findings:{' '}
                  {ioc.relatedFindingIds.join(', ') || 'None'}
                </td>
                <td className="py-3 px-4 font-mono text-slate-400">
                  {ioc.expiresAt.slice(0, 10)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ============================================================================
// 8. DEFENSIVE SECURITY OPERATIONS (SECOPS) VIEW
// ============================================================================
export const SecurityOperationsView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  return (
    <div className="space-y-6">
      <SectionHeader
        title="Defensive Security Operations (SOC) & Detection Engineering"
        subtitle="Normalized telemetry alert queue paired with versioned, MITRE ATT&CK-mapped detection rules and transparent match explanations."
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100">
            Normalized Security Alerts ({data.alerts.length})
          </h2>
          {data.alerts.map((alert) => (
            <div
              key={alert.id}
              className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2"
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <SeverityLabel severity={alert.severity} />
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300">{alert.id}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="font-mono text-cyan-300">{alert.status}</span>
                </div>
                <span className="font-mono text-slate-400">
                  Confidence: {alert.confidence}% · {alert.isSynthetic ? 'Synthetic Stream' : 'Live'}
                </span>
              </div>
              <div className="text-sm font-semibold text-slate-100">{alert.title}</div>
              <div className="text-xs text-slate-300">{alert.matchExplanation}</div>
              <pre className="p-2.5 bg-[#090D16] border border-slate-800 rounded text-[11px] font-mono text-slate-400 overflow-x-auto">
                {alert.normalizedEventJson}
              </pre>
            </div>
          ))}
        </div>

        <div className="lg:col-span-5 space-y-3">
          <h2 className="text-sm font-semibold text-slate-100">
            Versioned Detection Rules ({data.detectionRules.length})
          </h2>
          {data.detectionRules.map((rule) => (
            <div
              key={rule.id}
              className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2 text-xs"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="text-cyan-300 font-semibold">
                  {rule.id} (v{rule.version})
                </span>
                <span className="text-emerald-400">Test: {rule.testPassStatus}</span>
              </div>
              <div className="text-sm font-semibold text-slate-100">{rule.name}</div>
              <div className="text-slate-400 font-mono text-[11px]">{rule.mitreTechnique}</div>
              <div className="p-2 bg-[#090D16] border border-slate-800 rounded font-mono text-[11px] text-slate-300">
                {rule.queryExpression}
              </div>
              <div className="text-slate-400">{rule.rationale}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 9. INCIDENT RESPONSE VIEW
// ============================================================================
export const IncidentResponseView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<string>(Severity.HIGH);
  const [playbook, setPlaybook] = useState('PB-API-04: API Authorization Bypass Containment');
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    try {
      await apiClient.createIncident({
        projectId: data.currentProject.id,
        title: title.trim(),
        description: 'Initiated from Incident Response console.',
        severity,
        playbookName: playbook,
      });
      setTitle('');
      setFeedback('Incident opened and assigned to responder.');
      await onRefresh();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  const handleApproveContainment = async (incidentId: string, actionId: string) => {
    try {
      await apiClient.approveIncidentContainment(incidentId, actionId);
      setFeedback('Containment action approved and logged to immutable audit trail.');
      await onRefresh();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Incident Response & Playbook Containment"
        subtitle="Structured incident command with timelines, recovery checklists, and mandatory human approval for disruptive containment actions."
      />

      {feedback && (
        <div className="p-3 bg-[#0F1523] border border-cyan-500/40 rounded text-xs text-cyan-200">
          {feedback}
        </div>
      )}

      <form
        onSubmit={handleCreateIncident}
        className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3"
      >
        <h2 className="text-sm font-semibold text-slate-100">Declare New Security Incident</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label htmlFor="inc-title-input" className="block text-xs text-slate-400 mb-1">
              Incident Title
            </label>
            <input
              id="inc-title-input"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. INC-2026-042: Suspicious IAM Role Assumption"
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="inc-sev-select" className="block text-xs text-slate-400 mb-1">
              Severity
            </label>
            <select
              id="inc-sev-select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              {Object.values(Severity).map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="inc-pb-input" className="block text-xs text-slate-400 mb-1">
              Defensive Response Playbook
            </label>
            <input
              id="inc-pb-input"
              type="text"
              value={playbook}
              onChange={(e) => setPlaybook(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
        </div>
        <div className="flex justify-end">
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
          >
            Open Incident Record
          </button>
        </div>
      </form>

      <div className="space-y-4">
        {data.incidents.map((inc) => (
          <div
            key={inc.id}
            className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <SeverityLabel severity={inc.severity} />
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-cyan-300">{inc.id}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-amber-300">Status: {inc.status}</span>
                </div>
                <h3 className="mt-1 text-base font-semibold text-slate-100">{inc.title}</h3>
                <div className="text-xs text-slate-400">
                  Playbook: {inc.playbookName} · Commander: {inc.assignedResponder}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded space-y-2">
                <div className="font-semibold text-slate-200">
                  Containment Actions & Approval Gate
                </div>
                {inc.containmentActions.map((ca) => (
                  <div
                    key={ca.id}
                    className="flex items-center justify-between gap-2 py-1.5 border-b border-slate-800/60 last:border-0"
                  >
                    <div>
                      <div className="text-slate-200">{ca.actionTitle}</div>
                      <div className="font-mono text-[11px] text-slate-400">
                        {ca.impactLevel} · Status: {ca.approvalStatus}
                      </div>
                    </div>
                    {ca.approvalStatus === 'PENDING_APPROVAL' && (
                      <button
                        type="button"
                        onClick={() => handleApproveContainment(inc.id, ca.id)}
                        className="px-2.5 py-1 text-xs font-medium text-slate-950 bg-amber-400 hover:bg-amber-300 rounded whitespace-nowrap shrink-0"
                      >
                        Approve Containment
                      </button>
                    )}
                  </div>
                ))}
              </div>

              <div className="p-3 bg-[#090D16] border border-slate-800 rounded space-y-2">
                <div className="font-semibold text-slate-200">Incident Timeline</div>
                {inc.timeline.map((tl) => (
                  <div key={tl.id} className="text-slate-300">
                    <span className="font-mono text-[11px] text-slate-500">
                      [{tl.timestamp.slice(11, 19)}]
                    </span>{' '}
                    <span className="font-medium text-cyan-300">{tl.actor}:</span> {tl.entry}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 10. CLOUD AND CONTAINER SECURITY VIEW
// ============================================================================
export const CloudContainerSecurityView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  const cloudAssets = data.assets.filter(
    (a) =>
      a.type === 'CLOUD_RESOURCE' ||
      a.type === 'CONTAINER_K8S' ||
      a.type === 'IDENTITY' ||
      a.type === 'DATABASE'
  );
  const cloudFindings = data.findings.filter(
    (f) =>
      f.category === 'CLOUD_CONTAINER' ||
      f.category === 'IAM_IDENTITY' ||
      f.category === 'DEPENDENCY_SCA'
  );

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Cloud, Kubernetes & Container Supply-Chain Security"
        subtitle="Passive configuration review for AWS/GCP IAM trust policies, Kubernetes PodSecurityStandards, container image SBOMs, and Infrastructure-as-Code."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {cloudAssets.map((asset) => (
          <div
            key={asset.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2 text-xs"
          >
            <div className="flex items-center justify-between font-mono">
              <span className="text-cyan-300 font-semibold">{asset.displayName}</span>
              <span className="text-emerald-400">{asset.verificationStatus}</span>
            </div>
            <div className="font-mono text-slate-300">{asset.address}</div>
            <div className="text-slate-400">
              Stack: {asset.technologies.join(' · ')} · Criticality: {asset.criticality}
            </div>
            <div className="text-slate-400">{asset.notes}</div>
          </div>
        ))}
      </div>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Cloud IAM, Kubernetes & Container Image Findings ({cloudFindings.length})
        </h2>
        {cloudFindings.map((f) => (
          <div
            key={f.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-1.5 text-xs"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <SeverityLabel severity={f.severity} />
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span className="font-mono text-slate-300">{f.id}</span>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <VerificationLabel verified={f.isVerified} origin={f.executionOrigin} />
              </div>
              <span className="font-mono text-slate-400">{f.category}</span>
            </div>
            <div className="text-sm font-semibold text-slate-100">{f.title}</div>
            <div className="text-slate-400">{f.description}</div>
            <div className="text-emerald-300 font-medium">Remediation: {f.remediationPlan}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 11. WEB AND API SECURITY VIEW
// ============================================================================
export const WebApiSecurityView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  const webAssets = data.assets.filter(
    (a) => a.type === 'WEB_APP' || a.type === 'API_ENDPOINT' || a.type === 'DOMAIN'
  );
  const webFindings = data.findings.filter(
    (f) => f.category === 'WEB_API' || f.category === 'CRYPTO_TLS'
  );

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Web Application, OpenAPI & TLS Security Posture"
        subtitle="Non-destructive OAuth2/OIDC boundary verification, TLS 1.3 cipher validation, and HTTP security header compliance for scoped endpoints."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {webAssets.map((asset) => (
          <div
            key={asset.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2 text-xs"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100 text-sm">{asset.displayName}</span>
              <span className="font-mono text-emerald-400">{asset.verificationStatus}</span>
            </div>
            <div className="font-mono text-cyan-300">{asset.address}</div>
            <div className="text-slate-400">
              Technologies: {asset.technologies.join(' · ')}
            </div>
            <div className="font-mono text-[11px] text-slate-400">
              Services: {asset.openServices.map((s) => `${s.port}/${s.protocol} (${s.tlsStatus})`).join(', ')}
            </div>
          </div>
        ))}
      </div>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          Web, API & TLS Findings ({webFindings.length})
        </h2>
        {webFindings.map((f) => (
          <div
            key={f.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-1.5 text-xs"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <SeverityLabel severity={f.severity} />
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span className="font-mono text-slate-300">{f.id}</span>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <VerificationLabel verified={f.isVerified} origin={f.executionOrigin} />
              </div>
              <span className="font-mono text-slate-400">CWE: {f.cweId || 'N/A'}</span>
            </div>
            <div className="text-sm font-semibold text-slate-100">{f.title}</div>
            <div className="text-slate-400">{f.description}</div>
            <div className="text-emerald-300">Remediation: {f.remediationPlan}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 12. LABORATORY AND BENIGN ADVERSARY EMULATION VIEW
// ============================================================================
export const LaboratoryEmulationView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleRunScenario = async (scenarioId: string) => {
    setFeedback(null);
    try {
      const updated = await apiClient.executeLabScenario(scenarioId);
      setFeedback(
        `Executed benign lab scenario "${updated.name}" (${updated.executionStatus}). Detection coverage: ${updated.detectionCoveragePercent}%. Cleanup: ${updated.cleanupStatus}.`
      );
      await onRefresh();
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Controlled Laboratory & Benign Adversary Emulation"
        subtitle="Validates SIEM detection rules and incident containment playbooks in isolated lab subnets using strictly benign test actions and synthetic principals."
      />

      {feedback && (
        <div className="p-3 bg-[#0F1523] border border-emerald-500/40 rounded text-xs text-emerald-200">
          {feedback}
        </div>
      )}

      <div className="space-y-4">
        {data.labScenarios.map((lab) => (
          <div
            key={lab.id}
            className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-cyan-300 font-semibold">{lab.id}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-amber-300">Execution Mode: {lab.executionStatus}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-emerald-400">Cleanup: {lab.cleanupStatus}</span>
                </div>
                <h3 className="mt-1 text-base font-semibold text-slate-100">{lab.name}</h3>
                <div className="text-xs font-mono text-slate-400 mt-0.5">
                  MITRE: {lab.mitreMapping} · Synthetic Target: {lab.syntheticTarget} · Environment: {lab.labEnvironment}
                </div>
              </div>
              <button
                type="button"
                onClick={() => handleRunScenario(lab.id)}
                className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md whitespace-nowrap shrink-0"
              >
                Run Benign Emulation Check
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="font-semibold text-slate-200 mb-1">Safety Preconditions</div>
                <ul className="space-y-1 text-slate-400">
                  {lab.preconditions.map((p, i) => (
                    <li key={i}>• {p}</li>
                  ))}
                </ul>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="font-semibold text-slate-200 mb-1">Expected Detections</div>
                <ul className="space-y-1 text-cyan-300 font-mono text-[11px]">
                  {lab.expectedDetections.map((d, i) => (
                    <li key={i}>• {d}</li>
                  ))}
                </ul>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="font-semibold text-emerald-300 mb-1">
                  Observed Outcomes ({lab.detectionCoveragePercent}% Coverage)
                </div>
                <ul className="space-y-1 text-slate-300">
                  {lab.observedOutcomes.map((o, i) => (
                    <li key={i}>• {o}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="p-3 bg-[#090D16] border border-slate-800 rounded font-mono text-[11px] text-slate-400 space-y-1">
              {lab.logs.map((l, i) => (
                <div key={i}>{l}</div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
