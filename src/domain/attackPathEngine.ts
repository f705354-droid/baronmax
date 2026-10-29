import { BusinessCriticality, ComputedAttackPath, GraphEdge, GraphNode } from './types';

const CRITICALITY_WEIGHT: Record<BusinessCriticality, number> = {
  [BusinessCriticality.MISSION_CRITICAL]: 35,
  [BusinessCriticality.HIGH]: 25,
  [BusinessCriticality.MEDIUM]: 15,
  [BusinessCriticality.LOW]: 8,
};

const PRIVILEGE_WEIGHT: Record<GraphNode['privilegeLevel'], number> = {
  ROOT_CLUSTER: 30,
  ADMIN: 24,
  SERVICE_ACCOUNT: 16,
  USER: 10,
  UNPRIVILEGED: 4,
};

const EXPOSURE_WEIGHT: Record<GraphNode['exposure'], number> = {
  INTERNET_FACING: 25,
  INTERNAL_CORP: 12,
  ISOLATED_VPC: 5,
};

/**
 * Computes composite risk score for a sequence of graph nodes and edges based on:
 * - Entry node internet exposure
 * - Target node business criticality and privilege level
 * - Verified findings along the path
 * - Edge confidence and derivation (OBSERVED vs INFERRED_HYPOTHESIS)
 */
export function calculateAttackPathRisk(
  nodes: GraphNode[],
  edges: GraphEdge[]
): {
  compositeRiskScore: number;
  confidenceScore: number;
  derivation: 'OBSERVED' | 'INFERRED_HYPOTHESIS';
  chokePointNodeId: string;
} {
  if (nodes.length === 0) {
    return {
      compositeRiskScore: 0,
      confidenceScore: 0,
      derivation: 'INFERRED_HYPOTHESIS',
      chokePointNodeId: '',
    };
  }

  const entryNode = nodes[0];
  const crownJewelNode = nodes[nodes.length - 1];

  const exposureScore = EXPOSURE_WEIGHT[entryNode.exposure] ?? 10;
  const targetCriticalityScore = CRITICALITY_WEIGHT[crownJewelNode.criticality] ?? 15;
  const privilegeScore = PRIVILEGE_WEIGHT[crownJewelNode.privilegeLevel] ?? 10;

  const totalVerifiedFindings = nodes.reduce((sum, n) => sum + n.verifiedFindingsCount, 0);
  const findingsBonus = Math.min(20, totalVerifiedFindings * 6);

  const hasInferredEdge = edges.some((e) => e.derivation === 'INFERRED_HYPOTHESIS');
  const derivation: 'OBSERVED' | 'INFERRED_HYPOTHESIS' = hasInferredEdge
    ? 'INFERRED_HYPOTHESIS'
    : 'OBSERVED';

  const avgConfidence =
    edges.length > 0
      ? Math.round(edges.reduce((sum, e) => sum + e.confidence, 0) / edges.length)
      : 80;

  // Discount inferred hypotheses slightly compared to observed paths
  const rawScore = exposureScore + targetCriticalityScore + privilegeScore + findingsBonus;
  const derivationFactor = derivation === 'OBSERVED' ? 1.0 : 0.85;
  const compositeRiskScore = Math.min(100, Math.max(1, Math.round(rawScore * derivationFactor)));

  // Identify choke point (intermediate node with highest verified findings or privilege)
  let chokePoint = nodes[Math.min(1, nodes.length - 1)];
  for (const node of nodes.slice(1, -1)) {
    if (node.verifiedFindingsCount > chokePoint.verifiedFindingsCount) {
      chokePoint = node;
    }
  }

  return {
    compositeRiskScore,
    confidenceScore: avgConfidence,
    derivation,
    chokePointNodeId: chokePoint.id,
  };
}

export function discoverAttackPaths(
  projectId: string,
  nodes: GraphNode[],
  edges: GraphEdge[]
): ComputedAttackPath[] {
  const projectNodes = nodes.filter((n) => n.projectId === projectId);
  const projectEdges = edges.filter((e) => e.projectId === projectId);
  const nodeMap = new Map(projectNodes.map((n) => [n.id, n]));

  // Find paths from INTERNET_FACING nodes to HIGH / MISSION_CRITICAL assets
  const entryNodes = projectNodes.filter((n) => n.exposure === 'INTERNET_FACING');
  const discovered: ComputedAttackPath[] = [];

  for (const startNode of entryNodes) {
    const queue: { currentId: string; nodeIds: string[]; edgeIds: string[] }[] = [
      { currentId: startNode.id, nodeIds: [startNode.id], edgeIds: [] },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.nodeIds.length > 6) continue;

      const outgoing = projectEdges.filter(
        (e) =>
          e.source === current.currentId &&
          e.relationshipType !== 'MITIGATED_BY_CONTROL' &&
          !current.nodeIds.includes(e.target)
      );

      for (const edge of outgoing) {
        const nextNode = nodeMap.get(edge.target);
        if (!nextNode) continue;

        const nextNodeIds = [...current.nodeIds, nextNode.id];
        const nextEdgeIds = [...current.edgeIds, edge.id];

        if (
          nextNodeIds.length >= 3 &&
          (nextNode.criticality === BusinessCriticality.MISSION_CRITICAL ||
            nextNode.privilegeLevel === 'ROOT_CLUSTER' ||
            nextNode.privilegeLevel === 'ADMIN')
        ) {
          const pathNodes = nextNodeIds.map((id) => nodeMap.get(id)!);
          const pathEdges = nextEdgeIds.map((id) => projectEdges.find((e) => e.id === id)!);
          const metrics = calculateAttackPathRisk(pathNodes, pathEdges);
          const chokeNode = nodeMap.get(metrics.chokePointNodeId);

          discovered.push({
            id: `path-${startNode.id}-${nextNode.id}-${nextEdgeIds.length}`,
            projectId,
            title: `${startNode.label} → ${chokeNode?.label ?? 'Pivot'} → ${nextNode.label}`,
            nodeSequence: nextNodeIds,
            edgeSequence: nextEdgeIds,
            derivation: metrics.derivation,
            compositeRiskScore: metrics.compositeRiskScore,
            confidenceScore: metrics.confidenceScore,
            preconditions: [
              `Internet reachability to ${startNode.label}`,
              ...pathEdges.map((e) => `${e.relationshipType} (${e.derivation === 'OBSERVED' ? 'Observed' : 'Inferred Hypothesis'}, ${e.confidence}% confidence)`),
            ],
            chokePointNodeId: metrics.chokePointNodeId,
            recommendedControls: [
              `Restrict network ingress or enforce mTLS on ${chokeNode?.label ?? startNode.label}`,
              `Remediate verified findings on ${chokeNode?.label ?? startNode.label} and rotate scoped IAM credentials`,
              `Apply least-privilege IAM boundary before ${nextNode.label}`,
            ],
          });
        }

        queue.push({
          currentId: nextNode.id,
          nodeIds: nextNodeIds,
          edgeIds: nextEdgeIds,
        });
      }
    }
  }

  return discovered.sort((a, b) => b.compositeRiskScore - a.compositeRiskScore);
}
