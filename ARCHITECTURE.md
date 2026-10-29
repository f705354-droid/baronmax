# BARON NEXUS — Enterprise AI Cybersecurity Operations Platform
## Architecture, Security Controls & Verification Guide

### 1. System Architecture Overview

Baron Nexus is a full-stack TypeScript cybersecurity operations, authorized security assessment orchestration, vulnerability management, attack-path analysis, threat intelligence, and incident response platform.

- **Frontend (`src/`)**: React 19 + TypeScript + Tailwind CSS v4 SPA organized into modular domain views (`CoreOperationsViews.tsx`, `IntelligenceDefenseViews.tsx`, `GovernanceSystemViews.tsx`) and shared accessible components (`SharedUI.tsx`).
- **Backend (`server.ts`, `src/server/`)**: Express REST API versioned under `/api/v1/*` with Vite middleware integration in development and static asset serving in production.
- **Pure Security & Domain Engines (`src/domain/`)**:
  - `scopeEngine.ts`: Validates domains, wildcard subdomains, IPv4 CIDR ranges, explicit asset inclusions, explicit exclusions, time windows, and outbound SSRF protections (`169.254.169.254`, loopback, RFC1918).
  - `rbacEngine.ts`: Least-privilege Role-Based Access Control across 7 enterprise roles (`PLATFORM_ADMIN`, `SECURITY_MANAGER`, `SECURITY_ANALYST`, `PENETRATION_TESTER`, `INCIDENT_RESPONDER`, `AUDITOR`, `READ_ONLY_VIEWER`) with strict project-level isolation.
  - `jobStateMachine.ts`: Enforces `DRAFT -> SCOPE_VALIDATION -> AWAITING_APPROVAL -> QUEUED -> RUNNING -> COMPLETED / FAILED / CANCELLED` transitions and Global Emergency Stop.
  - `auditChain.ts`: Append-only SHA-256 cryptographically hash-chained audit trail with tamper detection (`verifyAuditChain`).
  - `attackPathEngine.ts`: Graph analysis engine calculating composite risk scores and distinguishing `OBSERVED` vs. `INFERRED_HYPOTHESIS` paths.
- **Persistent Repository (`src/server/storage.ts`)**: Atomic file-backed JSON persistence (`./data/baron-nexus-db.json`) with toggleable/removable synthetic demonstration records (`SYNTHETIC_DEMO`).

### 2. Setup, Testing & Deployment Instructions

1. **Environment Configuration**:
   Copy `.env.example` to `.env`. `GEMINI_API_KEY` is used strictly server-side in `src/server/aiCopilotService.ts` via `@google/genai` (`gemini-3.8-flash`).
2. **Run Unit Tests**:
   ```bash
   npx --yes tsx --test src/domain/securityEngines.test.ts
   ```
3. **Development Server**:
   ```bash
   npm run dev
   ```
4. **Production Build**:
   ```bash
   npm run build
   npm start
   ```

### 3. Known Limitations & External Provider Requirements

- **External Scanners & Live Network Probing**: Inside the hosted container sandbox, raw network sockets and third-party commercial scanners are represented through typed provider interfaces and clearly labeled `SIMULATED` / `PASSIVE_INSPECTION` modes. No fabricated live external scan results are ever claimed.
- **External Integrations (MISP, SIEM, AWS Cloud Config)**: Require external endpoint URLs and credentials in environment variables; all outbound test connections are protected by `validateOutboundUrlForSsrf`.
