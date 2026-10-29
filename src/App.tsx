import React, { useEffect, useState, useCallback } from 'react';
import { apiClient, OverviewPayload, SessionPayload } from './api/client';
import { AuthorizedScope } from './domain/types';
import {
  CommandPaletteModal,
  NAVIGATION_SECTIONS,
  NavSectionId,
  ScopeEditModal,
} from './components/SharedUI';
import {
  AICopilotView,
  AssessmentsOrchestratorView,
  AssetsSurfaceView,
  OverviewDashboardView,
  VulnerabilityManagementView,
} from './components/views/CoreOperationsViews';
import {
  AttackPathAnalysisView,
  CloudContainerSecurityView,
  IncidentResponseView,
  LaboratoryEmulationView,
  SecurityOperationsView,
  ThreatIntelligenceView,
  WebApiSecurityView,
} from './components/views/IntelligenceDefenseViews';
import {
  AuditLogView,
  IntegrationsView,
  PluginMarketplaceView,
  ReportsEvidenceView,
  SettingsView,
  SystemHealthView,
  TeamAccessControlView,
} from './components/views/GovernanceSystemViews';
import { LanSecurityView } from './components/views/LanSecurityView';

export function App() {
  const [activeSection, setActiveSection] = useState<NavSectionId>('overview');
  const [selectedProjectId, setSelectedProjectId] = useState<string>('proj-sovereign-cloud');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [session, setSession] = useState<SessionPayload | null>(null);
  const [overviewData, setOverviewData] = useState<OverviewPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isScopeModalOpen, setIsScopeModalOpen] = useState<boolean>(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState<boolean>(false);

  const loadData = useCallback(async (projectIdToLoad = selectedProjectId) => {
    try {
      setError(null);
      const [sess, ov] = await Promise.all([
        apiClient.getSession(),
        apiClient.getOverview(projectIdToLoad),
      ]);
      setSession(sess);
      setOverviewData(ov);
    } catch (err: any) {
      setError(err.message || 'تعذر تحميل بيانات منصة بارون نيكسوس.');
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    loadData(selectedProjectId);
  }, [selectedProjectId, loadData]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const handleSwitchUser = async (userId: string) => {
    try {
      await apiClient.switchUser(userId);
      await loadData('proj-sovereign-cloud');
      setSelectedProjectId('proj-sovereign-cloud');
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSaveScope = async (scopeId: string, updated: Partial<AuthorizedScope>) => {
    await apiClient.updateScope(scopeId, updated);
    await loadData(selectedProjectId);
  };

  const activeNavMeta =
    NAVIGATION_SECTIONS.find((s) => s.id === activeSection) ?? NAVIGATION_SECTIONS[0];

  const groups = [
    'العمليات الأساسية',
    'الاستخبارات ومسارات الهجوم',
    'الدفاع والتحقق الأمني',
    'الحوكمة وإدارة المنصة',
  ] as const;

  return (
    <div dir="rtl" className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col">
      {/* Top Bar following the strict 3-zone SaaS Dashboard Top Bar Contract */}
      <header className="h-14 border-b border-slate-800/90 bg-[#090D16] px-4 lg:px-6 flex items-center justify-between gap-4 sticky top-0 z-30">
        {/* Zone 1: Single-line Brand Title + Breadcrumb */}
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0 min-w-0">
          <button
            type="button"
            onClick={() => setSidebarCollapsed((c) => !c)}
            aria-label="طي أو توسيع القائمة الجانبية"
            className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-slate-100 bg-slate-900 border border-slate-800 rounded"
          >
            {sidebarCollapsed ? 'القائمة' : 'إخفاء القائمة'}
          </button>
          <span className="text-base font-bold tracking-tight text-slate-100">
            بارون نيكسوس
          </span>
          <span aria-hidden="true" className="text-slate-600 hidden sm:inline">
            /
          </span>
          <span className="text-xs text-slate-400 hidden lg:inline">
            {activeNavMeta.group}
          </span>
          <span aria-hidden="true" className="text-slate-600 hidden lg:inline">
            /
          </span>
          <span className="text-xs font-medium text-cyan-300 hidden sm:inline truncate max-w-[200px]">
            {activeNavMeta.label}
          </span>
        </div>

        {/* Zone 2: Project Selector & Command Search */}
        <div className="hidden md:flex items-center gap-3 min-w-0">
          {overviewData && (
            <div className="flex items-center gap-2 min-w-0">
              <label htmlFor="top-project-select" className="text-xs text-slate-400 whitespace-nowrap">
                المشروع النشط:
              </label>
              <select
                id="top-project-select"
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="px-2.5 py-1 text-xs font-mono bg-[#0F1523] border border-slate-800 rounded text-slate-100 max-w-[250px] truncate"
              >
                {overviewData.projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.code} — {p.name}
                  </option>
                ))}
              </select>
            </div>
          )}
          <button
            type="button"
            onClick={() => setIsCommandPaletteOpen(true)}
            className="px-3 py-1 text-xs text-slate-300 hover:text-slate-100 bg-[#0F1523] border border-slate-800 rounded-md whitespace-nowrap shrink-0"
          >
            لوحة الأوامر (Ctrl+K)
          </button>
        </div>

        {/* Zone 3: Active Operator Role & Primary Scope Action */}
        <div className="flex items-center gap-3 shrink-0">
          {session && (
            <button
              type="button"
              onClick={() => setActiveSection('team')}
              className="hidden sm:inline-block text-xs font-mono text-slate-300 hover:text-cyan-300 whitespace-nowrap"
            >
              {session.user.role}
            </button>
          )}
          <button
            type="button"
            onClick={() => setIsScopeModalOpen(true)}
            className="px-3.5 py-1.5 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            سجل النطاق المصرح
          </button>
        </div>
      </header>

      {/* Emergency Stop Banner if active */}
      {overviewData?.emergencyStopActive && (
        <div className="bg-rose-950/90 border-b border-rose-700 px-6 py-2.5 flex items-center justify-between text-xs text-rose-100">
          <div>
            <span className="font-semibold">تم تفعيل الإيقاف الطارئ الشامل:</span>{' '}
            {overviewData.emergencyStopReason || 'تم إيقاف جميع مهام التقييم الأمني الجارية فوراً.'}
          </div>
          <button
            type="button"
            onClick={async () => {
              await apiClient.setEmergencyStop(false);
              await loadData(selectedProjectId);
            }}
            className="px-3 py-1 bg-rose-700 hover:bg-rose-600 text-white rounded font-medium"
          >
            استعادة التشغيل الطبيعي
          </button>
        </div>
      )}

      {/* Main Workspace Body */}
      <div className="flex-1 flex min-h-0">
        {/* Right Navigation Sidebar in RTL (All 19 Mandatory Sections) */}
        <aside
          aria-label="القائمة الرئيسية للمنصة"
          className={`${
            sidebarCollapsed ? 'w-0 overflow-hidden border-l-0' : 'w-64 border-l border-slate-800/80'
          } bg-[#090D16] shrink-0 transition-all duration-150 flex flex-col justify-between`}
        >
          <nav className="p-3 space-y-5 overflow-y-auto">
            {groups.map((groupName) => (
              <div key={groupName}>
                <div className="px-2.5 text-[11px] font-semibold text-slate-500 tracking-tight mb-1.5">
                  {groupName}
                </div>
                <div className="space-y-0.5">
                  {NAVIGATION_SECTIONS.filter((item) => item.group === groupName).map((item) => {
                    const isActive = activeSection === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setActiveSection(item.id)}
                        className={`w-full text-right px-2.5 py-1.5 rounded-md text-xs font-medium flex items-center justify-between transition-colors whitespace-nowrap ${
                          isActive
                            ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                            : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
                        }`}
                      >
                        <span className="truncate">{item.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          {session && (
            <div className="p-3 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1">
              <div className="font-medium text-slate-200 truncate">{session.user.displayName}</div>
              <div className="font-mono text-cyan-400">{session.user.role}</div>
            </div>
          )}
        </aside>

        {/* Main Content Viewport */}
        <main className="flex-1 min-w-0 p-6 lg:p-8 overflow-y-auto max-w-[1440px]">
          {loading ? (
            <div className="p-8 bg-[#0F1523] border border-slate-800 rounded-lg text-sm text-slate-400 font-mono">
              جارٍ تحميل بيانات الموقف الأمني والتحقق من سلامة سلسلة التدقيق SHA-256...
            </div>
          ) : error ? (
            <div className="p-6 bg-rose-950/30 border border-rose-800 rounded-lg space-y-3">
              <div className="text-sm font-semibold text-rose-200">
                تم رفض العملية أو منع الوصول بموجب سياسة الصلاحيات
              </div>
              <div className="text-xs text-rose-300 font-mono">{error}</div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => loadData('proj-sovereign-cloud')}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-800 text-slate-100 rounded hover:bg-slate-700"
                >
                  إعادة المحاولة / العودة للمشروع المصرح
                </button>
                <button
                  type="button"
                  onClick={() => handleSwitchUser('usr-admin-01')}
                  className="px-3 py-1.5 text-xs font-medium bg-cyan-400 text-slate-950 rounded hover:bg-cyan-300"
                >
                  التبديل إلى حساب مدير المنصة (PLATFORM_ADMIN)
                </button>
              </div>
            </div>
          ) : overviewData ? (
            <>
              {activeSection === 'overview' && (
                <OverviewDashboardView
                  data={overviewData}
                  onNavigate={setActiveSection}
                  onOpenScopeModal={() => setIsScopeModalOpen(true)}
                />
              )}
              {activeSection === 'lan-security' && <LanSecurityView />}
              {activeSection === 'copilot' && (
                <AICopilotView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'assets' && (
                <AssetsSurfaceView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                  onOpenScopeModal={() => setIsScopeModalOpen(true)}
                />
              )}
              {activeSection === 'assessments' && (
                <AssessmentsOrchestratorView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                  onOpenScopeModal={() => setIsScopeModalOpen(true)}
                />
              )}
              {activeSection === 'vulnerabilities' && (
                <VulnerabilityManagementView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'attack-paths' && (
                <AttackPathAnalysisView data={overviewData} />
              )}
              {activeSection === 'threat-intel' && (
                <ThreatIntelligenceView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'secops' && (
                <SecurityOperationsView data={overviewData} />
              )}
              {activeSection === 'incidents' && (
                <IncidentResponseView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'cloud-container' && (
                <CloudContainerSecurityView data={overviewData} />
              )}
              {activeSection === 'web-api' && (
                <WebApiSecurityView data={overviewData} />
              )}
              {activeSection === 'laboratory' && (
                <LaboratoryEmulationView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'reports' && (
                <ReportsEvidenceView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'integrations' && (
                <IntegrationsView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'plugins' && (
                <PluginMarketplaceView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
              {activeSection === 'team' && (
                <TeamAccessControlView
                  data={overviewData}
                  session={session}
                  onSwitchUser={handleSwitchUser}
                />
              )}
              {activeSection === 'audit' && <AuditLogView data={overviewData} />}
              {activeSection === 'health' && <SystemHealthView data={overviewData} />}
              {activeSection === 'settings' && (
                <SettingsView
                  data={overviewData}
                  onRefresh={() => loadData(selectedProjectId)}
                />
              )}
            </>
          ) : null}
        </main>
      </div>

      <ScopeEditModal
        scope={overviewData?.scopes[0]}
        isOpen={isScopeModalOpen}
        onClose={() => setIsScopeModalOpen(false)}
        onSave={handleSaveScope}
      />

      <CommandPaletteModal
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectSection={(sec) => setActiveSection(sec)}
      />
    </div>
  );
}

export default App;
