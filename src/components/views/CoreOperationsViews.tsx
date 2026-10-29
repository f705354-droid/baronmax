import React, { useState } from 'react';
import { apiClient, OverviewPayload } from '../../api/client';
import {
  AssetType,
  BusinessCriticality,
  FindingStatus,
  JobStatus,
  Severity,
} from '../../domain/types';
import {
  MetricTile,
  NavSectionId,
  ScopeSummaryBanner,
  SectionHeader,
  SeverityLabel,
  VerificationLabel,
} from '../SharedUI';

const ENV_LABELS: Record<string, string> = {
  ALL: 'جميع البيئات',
  PRODUCTION: 'الإنتاج (PRODUCTION)',
  STAGING: 'الاختبار المسبق (STAGING)',
  CLOUD_INFRA: 'البنية السحابية (CLOUD_INFRA)',
  ISOLATED_LAB: 'المختبر المعزول (ISOLATED_LAB)',
};

// ============================================================================
// 1. OVERVIEW DASHBOARD VIEW (نظرة عامة)
// ============================================================================
export const OverviewDashboardView: React.FC<{
  data: OverviewPayload;
  onNavigate: (section: NavSectionId) => void;
  onOpenScopeModal: () => void;
}> = ({ data, onNavigate, onOpenScopeModal }) => {
  const [envFilter, setEnvFilter] = useState<string>('ALL');
  const [showOnboarding, setShowOnboarding] = useState<boolean>(false);

  const filteredAssets =
    envFilter === 'ALL'
      ? data.assets
      : data.assets.filter((a) => a.environment === envFilter);

  const verifiedFindings = data.findings.filter((f) => f.isVerified);
  const candidateFindings = data.findings.filter((f) => !f.isVerified);
  const criticalOpen = data.findings.filter(
    (f) =>
      f.severity === Severity.CRITICAL &&
      f.status !== FindingStatus.RESOLVED &&
      f.status !== FindingStatus.FALSE_POSITIVE
  );
  const activeIncidents = data.incidents.filter((i) => i.status !== 'CLOSED');
  const primaryScope = data.scopes[0];

  return (
    <div className="space-y-6">
      <SectionHeader
        title="لوحة القيادة التنفيذية والتقنية للعمليات الأمنية"
        subtitle={`الموقف الأمني اللحظي لمشروع ${data.currentProject.name} (${data.currentProject.code}). جميع المؤشرات مستمدة من السجلات المحفوظة فعلياً.`}
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowOnboarding((v) => !v)}
              className="px-3 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {showOnboarding ? 'إخفاء دليل التشغيل' : 'دليل سير العمل الآمن'}
            </button>
            <button
              type="button"
              onClick={() => onNavigate('assessments')}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              بدء تقييم أمني مصرح
            </button>
          </>
        }
      />

      <ScopeSummaryBanner scope={primaryScope} onOpenScopeModal={onOpenScopeModal} />

      {showOnboarding && (
        <div className="p-5 bg-[#0F1523] border border-cyan-500/40 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-cyan-300">
              منهجية التشغيل الآمن والتحقق المعتمد في منصة بارون نيكسوس
            </h2>
            <span className="text-xs font-mono text-slate-400">4 مراحل موثقة</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs text-slate-300">
            <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
              <div className="font-semibold text-slate-100">01. تحديد النطاق وقواعد الاشتباك</div>
              <p className="mt-1 text-slate-400">
                تحديد النطاقات، عناوين CIDR، النوافذ الزمنية، والأصول المستثناة قبل تشغيل أي فحص.
              </p>
            </div>
            <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
              <div className="font-semibold text-slate-100">02. حصر الأصول ومنع التكرار</div>
              <p className="mt-1 text-slate-400">
                تسجيل الخوادم، واجهات API، عناقيد Kubernetes، وهويات IAM مع تصنيف الأهمية ومستوى التعرض.
              </p>
            </div>
            <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
              <div className="font-semibold text-slate-100">03. تنفيذ مهام الفحص غير التدميري</div>
              <p className="mt-1 text-slate-400">
                يتحقق الخادم من النطاق قبل كل مهمة، وتتطلب الفحوصات الحساسة اعتماد مدير الأمن أولاً.
              </p>
            </div>
            <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
              <div className="font-semibold text-slate-100">04. التحقق بالأدلة والمعالجة</div>
              <p className="mt-1 text-slate-400">
                فصل الثغرات المؤكدة عن المرشحة، وتحليل مسارات الهجوم، وتصدير تقارير موثقة ببصمة SHA-256.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricTile
          label="إجمالي الأصول ضمن النطاق"
          value={filteredAssets.length}
          meta={`${filteredAssets.filter((a) => a.exposure === 'INTERNET_FACING').length} معرضة للإنترنت · ${filteredAssets.filter((a) => a.verificationStatus === 'EXCLUDED').length} مستثناة`}
          accent="cyan"
          onClick={() => onNavigate('assets')}
        />
        <MetricTile
          label="الثغرات المؤكدة مقابل المرشحة"
          value={`${verifiedFindings.length} / ${candidateFindings.length}`}
          meta={`${criticalOpen.length} حرجة مفتوحة · ${verifiedFindings.length} موثقة بالأدلة`}
          accent={criticalOpen.length > 0 ? 'rose' : 'emerald'}
          onClick={() => onNavigate('vulnerabilities')}
        />
        <MetricTile
          label="الحوادث النشطة والتنبيهات"
          value={`${activeIncidents.length} / ${data.alerts.length}`}
          meta={`${data.detectionRules.filter((r) => r.enabled).length} قاعدة كشف نشطة`}
          accent={activeIncidents.length > 0 ? 'amber' : 'emerald'}
          onClick={() => onNavigate('incidents')}
        />
        <MetricTile
          label="سلامة سلسلة التدقيق المشفرة"
          value={data.auditVerification.valid ? 'موثقة وسليمة' : 'تلاعب مكتشف'}
          meta={`${data.auditVerification.checkedCount} سجل متسلسل بـ SHA-256`}
          accent={data.auditVerification.valid ? 'emerald' : 'rose'}
          onClick={() => onNavigate('audit')}
        />
      </div>

      {/* Environment Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
        <div className="flex items-center gap-1 p-1 bg-[#0F1523] border border-slate-800 rounded-lg">
          {['ALL', 'PRODUCTION', 'STAGING', 'CLOUD_INFRA', 'ISOLATED_LAB'].map((env) => (
            <button
              key={env}
              type="button"
              onClick={() => setEnvFilter(env)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                envFilter === env
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {ENV_LABELS[env] || env}
            </button>
          ))}
        </div>
        <div className="text-xs text-slate-400 font-mono">
          نهاية نافذة التفويض: {primaryScope ? primaryScope.windowEnd.slice(0, 10) : 'N/A'} · الحد الأقصى للمعدل: {primaryScope?.maxRequestsPerSecond ?? 0} طلب/ثانية
        </div>
      </div>

      {/* Two-Column Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-7 bg-[#0F1523] border border-slate-800/80 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-slate-100">
                قائمة أولويات معالجة الثغرات والمرشحات قيد التحقق
              </h2>
              <button
                type="button"
                onClick={() => onNavigate('vulnerabilities')}
                className="text-xs text-cyan-400 hover:underline"
              >
                فتح سجل الثغرات الكامل
              </button>
            </div>
            <div className="divide-y divide-slate-800/70 mt-2">
              {data.findings.slice(0, 5).map((f) => (
                <div key={f.id} className="py-3 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-xs">
                      <SeverityLabel severity={f.severity} />
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="font-mono text-slate-400" dir="ltr">{f.id}</span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <VerificationLabel verified={f.isVerified} origin={f.executionOrigin} />
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100 truncate">
                      {f.title}
                    </div>
                    <div className="mt-0.5 text-xs text-slate-400 font-mono">
                      الأصل: {f.assetName} · الحالة: {f.status} · الثقة: {f.confidence}%
                    </div>
                  </div>
                  <span className="font-mono text-xs text-slate-400 shrink-0" dir="ltr">
                    CVSS {f.cvssScore?.toFixed(1) ?? 'N/A'}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>الثغرات المؤكدة مرتبطة بأدلة رقمية موثقة ببصمة SHA-256</span>
            <button
              type="button"
              onClick={() => onNavigate('copilot')}
              className="text-violet-400 hover:underline font-medium"
            >
              تحليل الأولويات عبر المساعد الذكي
            </button>
          </div>
        </div>

        <div className="lg:col-span-5 bg-[#0F1523] border border-slate-800/80 rounded-lg p-5 flex flex-col justify-between space-y-5">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-slate-100">
                أحدث مهام التقييم وطابور الاعتماد
              </h2>
              <button
                type="button"
                onClick={() => onNavigate('assessments')}
                className="text-xs text-cyan-400 hover:underline"
              >
                إدارة التقييمات
              </button>
            </div>
            <div className="divide-y divide-slate-800/70 mt-2">
              {data.jobs.slice(0, 4).map((job) => (
                <div key={job.id} className="py-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-300" dir="ltr">{job.id}</span>
                    <span
                      className={`font-mono font-medium ${
                        job.status === JobStatus.COMPLETED
                          ? 'text-emerald-400'
                          : job.status === JobStatus.AWAITING_APPROVAL
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {job.status}
                    </span>
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-100 truncate">
                    {job.title}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-400 font-mono truncate">
                    الأهداف: {job.requestedTargets.join(', ')} · النمط: {job.executionMode}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800">
            <div className="text-xs font-semibold text-slate-300 mb-2">
              حالة اتصال مزودي البيانات والتكاملات
            </div>
            <div className="space-y-1.5 text-xs">
              {data.integrations.map((int) => (
                <div key={int.id} className="flex items-center justify-between text-slate-400">
                  <span className="truncate">{int.name}</span>
                  <span
                    className={`font-mono ${
                      int.connectionStatus === 'CONNECTED_VERIFIED'
                        ? 'text-emerald-400'
                        : int.connectionStatus === 'SIMULATED_MODE'
                        ? 'text-cyan-400'
                        : 'text-amber-400'
                    }`}
                  >
                    {int.connectionStatus}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 2. AI SECURITY COPILOT VIEW (المساعد الأمني الذكي)
// ============================================================================
export const AICopilotView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [prompt, setPrompt] = useState('');
  const [selectedTool, setSelectedTool] = useState<string>('prioritize_remediation');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!prompt.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await apiClient.queryCopilot({
        projectId: data.currentProject.id,
        prompt: prompt.trim(),
        toolId: selectedTool,
      });
      setPrompt('');
      await onRefresh();
    } catch (err: any) {
      setError(err.message || 'تعذر الاتصال بالمساعد الأمني الذكي.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickPrompt = async (toolId: string, presetText: string) => {
    setSelectedTool(toolId);
    setLoading(true);
    setError(null);
    try {
      await apiClient.queryCopilot({
        projectId: data.currentProject.id,
        prompt: presetText,
        toolId,
      });
      await onRefresh();
    } catch (err: any) {
      setError(err.message || 'تعذر تنفيذ أداة المساعد الأمني الذكي.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = async () => {
    await apiClient.clearCopilotConversation(data.currentProject.id);
    await onRefresh();
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="المساعد الأمني الذكي (تحليل مدعوم بالأدلة عبر الخادم)"
        subtitle="تحليل أمني مهيكل مرتبط بثغرات المشروع المؤكدة، مسارات الهجوم، وأدلة SHA-256 مع عزل كامل لمدخلات السجلات غير الموثوقة."
        actions={
          <button
            type="button"
            onClick={handleClear}
            className="px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-md"
          >
            مسح سجل المحادثة
          </button>
        }
      />

      {error && (
        <div className="p-3 bg-rose-950/40 border border-rose-700 rounded-md text-xs text-rose-200">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 space-y-4">
          <div className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3">
            <h2 className="text-sm font-semibold text-violet-300">
              سجل أدوات التحليل المصرح بها
            </h2>
            <p className="text-xs text-slate-400">
              لا يمتلك المساعد الذكي أي وصول مباشر لسطر الأوامر، ويعمل حصرياً عبر أدوات قراءة وتلخيص محكومة بالصلاحيات.
            </p>
            <div className="space-y-2">
              {data.copilotTools.map((tool) => (
                <button
                  key={tool.id}
                  type="button"
                  onClick={() =>
                    handleQuickPrompt(
                      tool.id,
                      `قم بتنفيذ أداة ${tool.name} لمشروع ${data.currentProject.name} مع الاستشهاد بمعرفات الأدلة.`
                    )
                  }
                  disabled={loading}
                  className={`w-full text-right p-3 rounded-md border transition-colors ${
                    selectedTool === tool.id
                      ? 'bg-violet-950/30 border-violet-500/50 text-slate-100'
                      : 'bg-[#090D16] border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="text-xs font-semibold text-violet-300">{tool.name}</div>
                  <div className="mt-1 text-xs text-slate-400">{tool.description}</div>
                  <div className="mt-1.5 text-[11px] font-mono text-slate-500" dir="ltr">
                    Permission: {tool.requiredPermission} · Mode: {tool.sideEffectLevel}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-8 bg-[#0F1523] border border-slate-800/80 rounded-lg flex flex-col h-[560px]">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>سياق المشروع: {data.currentProject.name}</span>
            <span className="font-mono text-violet-300">عزل المدخلات غير الموثوقة: مفعّل</span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {data.aiConversation.length === 0 ? (
              <div className="text-center py-12 text-sm text-slate-400">
                لا توجد رسائل في جلسة المشروع الحالية. اختر أداة من القائمة أو اكتب سؤالك أدناه.
              </div>
            ) : (
              data.aiConversation.map((msg) => (
                <div
                  key={msg.id}
                  className={`p-4 rounded-lg border ${
                    msg.role === 'user'
                      ? 'bg-[#090D16] border-slate-800 mr-8'
                      : 'bg-slate-900/90 border-violet-500/30 ml-4'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span className="font-semibold text-slate-200">
                      {msg.role === 'user' ? 'المشغل المصرح' : 'المساعد الأمني الذكي (Baron AI Copilot)'}
                    </span>
                    <span className="font-mono" dir="ltr">{msg.timestamp.slice(11, 19)} UTC</span>
                  </div>
                  <div className="text-sm text-slate-200 whitespace-pre-line leading-relaxed">
                    {msg.content}
                  </div>
                  {msg.role === 'assistant' && (
                    <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-xs text-slate-400 space-y-1 font-mono">
                      <div>
                        الثغرات المرجعية: {msg.referencedFindingIds.join(', ') || 'لا يوجد'} · الأصول: {msg.referencedAssetIds.join(', ') || 'لا يوجد'} · الأدلة: {msg.referencedEvidenceIds.join(', ') || 'لا يوجد'}
                      </div>
                      {msg.confidenceNote && (
                        <div className="text-violet-300">{msg.confidenceNote}</div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          <form onSubmit={handleSend} className="p-3 border-t border-slate-800 flex items-center gap-2">
            <label htmlFor="copilot-prompt-input" className="sr-only">
              اسأل المساعد الأمني الذكي
            </label>
            <input
              id="copilot-prompt-input"
              type="text"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="اسأل عن الثغرات المؤكدة، نقاط الاختناق في مسارات الهجوم، أو خطة المعالجة..."
              className="flex-1 px-3 py-2 text-sm bg-[#090D16] border border-slate-700 rounded-md text-slate-100"
            />
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-white bg-violet-600 hover:bg-violet-500 rounded-md whitespace-nowrap shrink-0"
            >
              {loading ? 'جارٍ التحليل...' : 'تشغيل التحليل الذكي'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 3. ASSETS AND ATTACK SURFACE VIEW (الأصول وسطح الهجوم)
// ============================================================================
export const AssetsSurfaceView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
  onOpenScopeModal: () => void;
}> = ({ data, onRefresh, onOpenScopeModal }) => {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [displayName, setDisplayName] = useState('');
  const [address, setAddress] = useState('');
  const [type, setType] = useState<string>(AssetType.API_ENDPOINT);
  const [criticality, setCriticality] = useState<string>(BusinessCriticality.HIGH);
  const [exposure, setExposure] = useState<string>('INTERNET_FACING');
  const [owner] = useState('فريق هندسة المنصات الأساسية');
  const [tags] = useState('production, scoped');
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const filteredAssets = data.assets.filter((a) => {
    const matchesSearch =
      a.displayName.toLowerCase().includes(search.toLowerCase()) ||
      a.address.toLowerCase().includes(search.toLowerCase()) ||
      a.tags.some((t) => t.toLowerCase().includes(search.toLowerCase()));
    const matchesType = typeFilter === 'ALL' || a.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    if (!displayName.trim() || !address.trim()) {
      setFeedback({ type: 'err', text: 'يرجى إدخال اسم الأصل والعنوان/النطاق.' });
      return;
    }
    try {
      const created = await apiClient.createAsset({
        projectId: data.currentProject.id,
        displayName: displayName.trim(),
        address: address.trim(),
        type,
        environment: data.currentProject.environment,
        criticality,
        exposure,
        owner,
        tags,
      });
      setDisplayName('');
      setAddress('');
      setFeedback({
        type: 'ok',
        text: `تم تسجيل الأصل "${created.displayName}" (${created.address}) — حالة النطاق: ${created.verificationStatus}.`,
      });
      await onRefresh();
    } catch (err: any) {
      setFeedback({ type: 'err', text: err.message });
    }
  };

  const handleExportCsv = () => {
    const headers = ['ID,DisplayName,Address,Type,Environment,Criticality,Exposure,ScopeStatus,Synthetic'];
    const rows = filteredAssets.map((a) =>
      [a.id, `"${a.displayName}"`, a.address, a.type, a.environment, a.criticality, a.exposure, a.verificationStatus, a.isSynthetic].join(',')
    );
    const blob = new Blob([[...headers, ...rows].join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `baron-assets-${data.currentProject.code}.csv`;
    link.click();
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="سجل الأصول وإدارة سطح الهجوم المصرح به"
        subtitle="جرد موحد مع منع التكرار للنطاقات، واجهات API، الخوادم، عناقيد Kubernetes، قواعد البيانات، وهويات IAM بعد التحقق من النطاق."
        actions={
          <button
            type="button"
            onClick={handleExportCsv}
            className="px-3 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md whitespace-nowrap shrink-0"
          >
            تصدير السجل (CSV)
          </button>
        }
      />

      <ScopeSummaryBanner scope={data.scopes[0]} onOpenScopeModal={onOpenScopeModal} />

      <form
        onSubmit={handleCreateAsset}
        className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">
            تسجيل أصل جديد ضمن المشروع (مع فحص النطاق ومنع التكرار تلقائياً)
          </h2>
          <span className="text-xs font-mono text-slate-400">المشروع: {data.currentProject.code}</span>
        </div>

        {feedback && (
          <div
            className={`p-3 rounded-md text-xs ${
              feedback.type === 'ok'
                ? 'bg-emerald-950/40 border border-emerald-700 text-emerald-200'
                : 'bg-rose-950/40 border border-rose-700 text-rose-200'
            }`}
          >
            {feedback.text}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
          <div className="lg:col-span-2">
            <label htmlFor="asset-name-input" className="block text-xs text-slate-400 mb-1">
              اسم الأصل التعريفي
            </label>
            <input
              id="asset-name-input"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="مثال: بوابة مفاتيح التشفير Vault"
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div className="lg:col-span-2">
            <label htmlFor="asset-address-input" className="block text-xs text-slate-400 mb-1">
              النطاق أو عنوان IP أو الرابط
            </label>
            <input
              id="asset-address-input"
              type="text"
              dir="ltr"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="vault.baron-corp.internal"
              className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="asset-type-select" className="block text-xs text-slate-400 mb-1">
              نوع الأصل
            </label>
            <select
              id="asset-type-select"
              value={type}
              onChange={(e) => setType(e.target.value)}
              className="w-full px-2.5 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              {Object.values(AssetType).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="asset-crit-select" className="block text-xs text-slate-400 mb-1">
              درجة الأهمية
            </label>
            <select
              id="asset-crit-select"
              value={criticality}
              onChange={(e) => setCriticality(e.target.value)}
              className="w-full px-2.5 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              {Object.values(BusinessCriticality).map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-3 text-xs">
            <label htmlFor="asset-exposure-select" className="text-slate-400">
              مستوى التعرض:
            </label>
            <select
              id="asset-exposure-select"
              value={exposure}
              onChange={(e) => setExposure(e.target.value)}
              className="px-2.5 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              <option value="INTERNET_FACING">معرض للإنترنت (INTERNET_FACING)</option>
              <option value="INTERNAL_CORP">شبكة داخلية (INTERNAL_CORP)</option>
              <option value="ISOLATED_VPC">سحابة معزولة (ISOLATED_VPC)</option>
              <option value="AIR_GAPPED">معزول فيزيائياً (AIR_GAPPED)</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md whitespace-nowrap shrink-0"
          >
            تسجيل الأصل في الجرد
          </button>
        </div>
      </form>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1 min-w-[260px]">
          <label htmlFor="asset-search-input" className="sr-only">
            تصفية الأصول
          </label>
          <input
            id="asset-search-input"
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="بحث باسم الأصل، النطاق، أو الوسم..."
            className="w-full max-w-md px-3 py-2 text-xs bg-[#0F1523] border border-slate-800 rounded-md text-slate-100"
          />
          <select
            aria-label="تصفية حسب نوع الأصل"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 text-xs bg-[#0F1523] border border-slate-800 rounded-md text-slate-200"
          >
            <option value="ALL">جميع أنواع الأصول</option>
            {Object.values(AssetType).map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className="text-xs font-mono text-slate-400">
          عرض {filteredAssets.length} من أصل {data.assets.length}
        </div>
      </div>

      <div className="bg-[#0F1523] border border-slate-800/80 rounded-lg overflow-x-auto">
        <table className="w-full text-right border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400">
              <th className="py-3 px-4">الأصل والعنوان</th>
              <th className="py-3 px-4">النوع والبيئة</th>
              <th className="py-3 px-4">الأهمية ومستوى التعرض</th>
              <th className="py-3 px-4">حالة التحقق من النطاق</th>
              <th className="py-3 px-4">المصدر والمالك</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {filteredAssets.map((asset) => (
              <tr key={asset.id} className="hover:bg-slate-800/30">
                <td className="py-3 px-4">
                  <div className="font-medium text-slate-100">{asset.displayName}</div>
                  <div className="font-mono text-cyan-300 mt-0.5" dir="ltr">{asset.address}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {asset.technologies.join(' · ')}
                  </div>
                </td>
                <td className="py-3 px-4 font-mono text-slate-300">
                  <div>{asset.type}</div>
                  <div className="text-slate-400 text-[11px]">{asset.environment}</div>
                </td>
                <td className="py-3 px-4 font-mono">
                  <div
                    className={
                      asset.criticality === BusinessCriticality.MISSION_CRITICAL
                        ? 'text-rose-400 font-semibold'
                        : 'text-amber-300'
                    }
                  >
                    {asset.criticality}
                  </div>
                  <div className="text-slate-400 text-[11px]">{asset.exposure}</div>
                </td>
                <td className="py-3 px-4 font-mono">
                  <span
                    className={
                      asset.verificationStatus === 'VERIFIED_IN_SCOPE'
                        ? 'text-emerald-400 font-medium'
                        : asset.verificationStatus === 'EXCLUDED'
                        ? 'text-rose-400 font-semibold'
                        : 'text-amber-400'
                    }
                  >
                    {asset.verificationStatus === 'VERIFIED_IN_SCOPE'
                      ? 'ضمن النطاق (VERIFIED_IN_SCOPE)'
                      : asset.verificationStatus === 'EXCLUDED'
                      ? 'مستثنى صراحةً (EXCLUDED)'
                      : asset.verificationStatus}
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-400">
                  <div>{asset.isSynthetic ? 'بيانات محاكاة (Synthetic)' : 'مسجل بواسطة المشغل'}</div>
                  <div className="font-mono text-[11px] text-slate-500">
                    المالك: {asset.owner}
                  </div>
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
// 4. ASSESSMENTS & SCOPE ORCHESTRATION VIEW (التقييمات الأمنية)
// ============================================================================
export const AssessmentsOrchestratorView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
  onOpenScopeModal: () => void;
}> = ({ data, onRefresh, onOpenScopeModal }) => {
  const [selectedProfileId, setSelectedProfileId] = useState(
    data.assessmentProfiles[0]?.id || 'prof-passive-recon'
  );
  const [jobTitle, setJobTitle] = useState('');
  const [targetInput, setTargetInput] = useState('payments.api.baron-financial.io');
  const [preCheckMessage, setPreCheckMessage] = useState<{ allowed: boolean; text: string } | null>(
    null
  );
  const [jobFeedback, setJobFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handlePreCheckScope = async () => {
    setPreCheckMessage(null);
    try {
      const res = await apiClient.validateTargetScope({
        projectId: data.currentProject.id,
        target: targetInput.split(',')[0].trim(),
        requiresActiveProbing: true,
      });
      setPreCheckMessage({
        allowed: res.allowed,
        text: `${res.allowed ? 'مسموح ضمن النطاق' : `مرفوض أمنياً (${res.rejectionCode})`}: ${res.reason}`,
      });
    } catch (err: any) {
      setPreCheckMessage({ allowed: false, text: err.message });
    }
  };

  const handleCreateJob = async (e: React.FormEvent) => {
    e.preventDefault();
    setJobFeedback(null);
    const targets = targetInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    if (targets.length === 0) {
      setJobFeedback({ ok: false, text: 'يرجى إدخال هدف واحد على الأقل.' });
      return;
    }
    setSubmitting(true);
    try {
      const created = await apiClient.createAssessmentJob({
        projectId: data.currentProject.id,
        profileId: selectedProfileId,
        title: jobTitle.trim() || `مهمة تقييم أمني — ${targets.join(', ')}`,
        requestedTargets: targets,
      });
      setJobTitle('');
      setJobFeedback({
        ok: true,
        text: `تم إنشاء المهمة ${created.id} بحالة ${created.status} بعد اجتياز فحص النطاق على الخادم.`,
      });
      await onRefresh();
    } catch (err: any) {
      setJobFeedback({ ok: false, text: err.message });
      await onRefresh();
    } finally {
      setSubmitting(false);
    }
  };

  const handleApproveJob = async (jobId: string) => {
    try {
      await apiClient.approveAssessmentJob(jobId);
      setJobFeedback({
        ok: true,
        text: `تم اعتماد وتنفيذ المهمة ${jobId} وتوليد الأدلة الموثقة بـ SHA-256.`,
      });
      await onRefresh();
    } catch (err: any) {
      setJobFeedback({ ok: false, text: err.message });
    }
  };

  const handleCancelJob = async (jobId: string) => {
    try {
      await apiClient.cancelAssessmentJob(jobId);
      await onRefresh();
    } catch (err: any) {
      setJobFeedback({ ok: false, text: err.message });
    }
  };

  const handleToggleEmergencyStop = async () => {
    try {
      await apiClient.setEmergencyStop(
        !data.emergencyStopActive,
        !data.emergencyStopActive
          ? 'قام المشغل بتفعيل الإيقاف الطارئ الشامل لجميع الفحوصات.'
          : undefined
      );
      await onRefresh();
    } catch (err: any) {
      setJobFeedback({ ok: false, text: err.message });
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="محرك تنسيق التقييمات الأمنية والاستطلاع المصرح به"
        subtitle="دورة حياة صارمة للمهام (DRAFT → SCOPE_VALIDATION → AWAITING_APPROVAL → QUEUED → RUNNING → COMPLETED / CANCELLED) مع تحقق إلزامي من النطاق على الخادم."
        actions={
          <button
            type="button"
            onClick={handleToggleEmergencyStop}
            className={`px-4 py-2 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 ${
              data.emergencyStopActive
                ? 'bg-emerald-500 text-slate-950 hover:bg-emerald-400'
                : 'bg-rose-600 text-white hover:bg-rose-500'
            }`}
          >
            {data.emergencyStopActive
              ? 'إلغاء الإيقاف الطارئ واستئناف العمل'
              : 'تفعيل الإيقاف الطارئ الشامل (Kill-Switch)'}
          </button>
        }
      />

      <ScopeSummaryBanner scope={data.scopes[0]} onOpenScopeModal={onOpenScopeModal} />

      <form
        onSubmit={handleCreateJob}
        className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">
            إطلاق مهمة تقييم أمني أو استطلاع مصرح به
          </h2>
          <span className="font-mono text-xs text-cyan-400">
            الفحوصات التدميرية: معطلة بموجب السياسة
          </span>
        </div>

        {jobFeedback && (
          <div
            className={`p-3 rounded-md text-xs ${
              jobFeedback.ok
                ? 'bg-emerald-950/40 border border-emerald-700 text-emerald-200'
                : 'bg-rose-950/40 border border-rose-700 text-rose-200'
            }`}
          >
            {jobFeedback.text}
          </div>
        )}

        {preCheckMessage && (
          <div
            className={`p-3 rounded-md text-xs font-mono ${
              preCheckMessage.allowed
                ? 'bg-cyan-950/40 border border-cyan-700 text-cyan-200'
                : 'bg-amber-950/40 border border-amber-700 text-amber-200'
            }`}
          >
            {preCheckMessage.text}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label htmlFor="job-profile-select" className="block text-xs text-slate-400 mb-1">
              ملف التقييم الأمني (Assessment Profile)
            </label>
            <select
              id="job-profile-select"
              value={selectedProfileId}
              onChange={(e) => setSelectedProfileId(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            >
              {data.assessmentProfiles.map((prof) => (
                <option key={prof.id} value={prof.id}>
                  {prof.name} ({prof.requiresApproval ? 'يتطلب موافقة' : 'تنفيذ آمن فوري'})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="job-targets-input" className="block text-xs text-slate-400 mb-1">
              الأهداف المطلوبة (مفصولة بفواصل)
            </label>
            <input
              id="job-targets-input"
              type="text"
              dir="ltr"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="payments.api.baron-financial.io"
              className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>

          <div>
            <label htmlFor="job-title-input" className="block text-xs text-slate-400 mb-1">
              عنوان المهمة / المرجع
            </label>
            <input
              id="job-title-input"
              type="text"
              value={jobTitle}
              onChange={(e) => setJobTitle(e.target.value)}
              placeholder="مثال: فحص تهيئة TLS والترويسات الأمنية"
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handlePreCheckScope}
              className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md"
            >
              فحص الهدف مقابل النطاق
            </button>
            <button
              type="button"
              onClick={() => setTargetInput('swift-hsm-prod.baron-corp.internal')}
              className="px-3 py-1.5 text-xs text-rose-300 bg-rose-950/30 border border-rose-800/50 rounded-md hover:bg-rose-950/50"
            >
              تعبئة هدف مستثنى (اختبار الرفض)
            </button>
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
          >
            {submitting ? 'جارٍ التحقق من النطاق...' : 'التحقق من النطاق وإرسال المهمة'}
          </button>
        </div>
      </form>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          طابور مهام التقييم وسجل التنفيذ ({data.jobs.length})
        </h2>
        {data.jobs.map((job) => (
          <div
            key={job.id}
            className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-cyan-300 font-semibold" dir="ltr">{job.id}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span
                    className={
                      job.status === JobStatus.COMPLETED
                        ? 'text-emerald-400 font-semibold'
                        : job.status === JobStatus.AWAITING_APPROVAL
                        ? 'text-amber-400 font-semibold'
                        : job.status === JobStatus.CANCELLED
                        ? 'text-rose-400'
                        : 'text-slate-300'
                    }
                  >
                    الحالة: {job.status}
                  </span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="text-slate-400">نمط المزود: {job.executionMode}</span>
                </div>
                <div className="mt-1 text-sm font-semibold text-slate-100">{job.title}</div>
                <div className="text-xs text-slate-400 font-mono mt-0.5">
                  الملف: {job.profileName} · الأهداف: {job.requestedTargets.join(', ')}
                </div>
              </div>

              <div className="flex items-center gap-2">
                {job.status === JobStatus.AWAITING_APPROVAL && (
                  <button
                    type="button"
                    onClick={() => handleApproveJob(job.id)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-md"
                  >
                    اعتماد وتنفيذ المهمة
                  </button>
                )}
                {(job.status === JobStatus.AWAITING_APPROVAL ||
                  job.status === JobStatus.QUEUED ||
                  job.status === JobStatus.RUNNING) && (
                  <button
                    type="button"
                    onClick={() => handleCancelJob(job.id)}
                    className="px-3 py-1.5 text-xs font-medium text-rose-200 bg-rose-950/50 border border-rose-800 rounded-md hover:bg-rose-900/60"
                  >
                    إلغاء المهمة
                  </button>
                )}
              </div>
            </div>

            <div className="p-3 bg-[#090D16] border border-slate-800/80 rounded text-xs font-mono space-y-1" dir="ltr">
              {job.logs.map((log, i) => (
                <div key={i} className="text-slate-300 text-left">
                  <span className="text-slate-500">[{log.timestamp.slice(11, 19)}]</span>{' '}
                  <span className={log.level === 'WARN' ? 'text-amber-400' : 'text-cyan-400'}>
                    {log.level}
                  </span>{' '}
                  {log.message}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 5. VULNERABILITY MANAGEMENT & SAFE VALIDATION VIEW (إدارة الثغرات)
// ============================================================================
export const VulnerabilityManagementView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [verificationFilter, setVerificationFilter] = useState<'ALL' | 'VERIFIED' | 'CANDIDATE'>('ALL');
  const [showImportForm, setShowImportForm] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<string>(Severity.HIGH);
  const [newCve, setNewCve] = useState('');
  const [newRemediation, setNewRemediation] = useState('');
  const [feedback, setFeedback] = useState<string | null>(null);

  const filtered = data.findings.filter((f) => {
    const matchStatus = statusFilter === 'ALL' || f.status === statusFilter;
    const matchVer =
      verificationFilter === 'ALL' ||
      (verificationFilter === 'VERIFIED' && f.isVerified) ||
      (verificationFilter === 'CANDIDATE' && !f.isVerified);
    return matchStatus && matchVer;
  });

  const handleStatusChange = async (findingId: string, nextStatus: string) => {
    setFeedback(null);
    try {
      const justification =
        nextStatus === FindingStatus.ACCEPTED_RISK
          ? 'تم التحقق من وجود ضوابط تعويضية عبر جدار WAF ومرشح Envoy OPA حتى إصدار الربع القادم.'
          : undefined;
      await apiClient.updateFindingStatus(findingId, nextStatus, justification);
      setFeedback(`تم تحديث حالة الثغرة ${findingId} إلى ${nextStatus}.`);
      await onRefresh();
    } catch (err: any) {
      setFeedback(`خطأ: ${err.message}`);
    }
  };

  const handleImportFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      await apiClient.importFinding({
        projectId: data.currentProject.id,
        assetId: data.assets[0]?.id,
        title: newTitle.trim(),
        severity: newSeverity,
        category: 'WEB_API',
        cveId: newCve.trim() || undefined,
        description: 'ثغرة مرشحة مستوردة بانتظار التحقق غير التدميري.',
        remediationPlan: newRemediation.trim() || 'تطبيق التحديث الأمني وإعادة الفحص.',
      });
      setNewTitle('');
      setNewCve('');
      setNewRemediation('');
      setShowImportForm(false);
      setFeedback('تم استيراد الثغرة إلى طابور (تحتاج إلى تحقق NEEDS_VALIDATION).');
      await onRefresh();
    } catch (err: any) {
      setFeedback(`خطأ: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="إدارة دورة حياة الثغرات والتحقق الآمن"
        subtitle="دورة حياة متكاملة من 9 حالات مع فصل صارم بين الثغرات المؤكدة بالأدلة والمرشحات غير المؤكدة."
        actions={
          <button
            type="button"
            onClick={() => setShowImportForm((v) => !v)}
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
          >
            {showImportForm ? 'إغلاق نموذج الاستيراد' : 'استيراد تقرير SARIF / ثغرة مرشحة'}
          </button>
        }
      />

      {feedback && (
        <div className="p-3 bg-[#0F1523] border border-cyan-500/40 rounded-md text-xs text-cyan-200">
          {feedback}
        </div>
      )}

      {showImportForm && (
        <form
          onSubmit={handleImportFinding}
          className="p-5 bg-[#0F1523] border border-slate-700 rounded-lg space-y-4"
        >
          <h2 className="text-sm font-semibold text-slate-100">
            استيراد ثغرة مرشحة جديدة (مع منع التكرار تلقائياً)
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label htmlFor="fnd-title-input" className="block text-xs text-slate-400 mb-1">
                عنوان الثغرة
              </label>
              <input
                id="fnd-title-input"
                type="text"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="مثال: تفعيل GraphQL Introspection في بيئة الإنتاج"
                className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
              />
            </div>
            <div>
              <label htmlFor="fnd-sev-select" className="block text-xs text-slate-400 mb-1">
                مستوى الخطورة
              </label>
              <select
                id="fnd-sev-select"
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value)}
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
              <label htmlFor="fnd-cve-input" className="block text-xs text-slate-400 mb-1">
                معرف CVE (اختياري)
              </label>
              <input
                id="fnd-cve-input"
                type="text"
                dir="ltr"
                value={newCve}
                onChange={(e) => setNewCve(e.target.value)}
                placeholder="CVE-2025-1029"
                className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
            >
              إدراج في طابور التحقق
            </button>
          </div>
        </form>
      )}

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-1 p-1 bg-[#0F1523] border border-slate-800 rounded-lg">
          {(['ALL', 'VERIFIED', 'CANDIDATE'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setVerificationFilter(mode)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                verificationFilter === mode
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {mode === 'ALL'
                ? `جميع النتائج (${data.findings.length})`
                : mode === 'VERIFIED'
                ? `مؤكدة بالأدلة (${data.findings.filter((f) => f.isVerified).length})`
                : `مرشحة قيد التحقق (${data.findings.filter((f) => !f.isVerified).length})`}
            </button>
          ))}
        </div>

        <select
          aria-label="تصفية حسب حالة الثغرة"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 text-xs bg-[#0F1523] border border-slate-800 rounded-md text-slate-200"
        >
          <option value="ALL">جميع حالات دورة الحياة (9 حالات)</option>
          {Object.values(FindingStatus).map((st) => (
            <option key={st} value={st}>
              {st}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-4">
        {filtered.map((f) => (
          <div
            key={f.id}
            className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <SeverityLabel severity={f.severity} />
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="font-mono text-slate-300" dir="ltr">{f.id}</span>
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <VerificationLabel verified={f.isVerified} origin={f.executionOrigin} />
                  {f.cveId && (
                    <>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="font-mono text-amber-300" dir="ltr">{f.cveId}</span>
                    </>
                  )}
                  <span aria-hidden="true" className="text-slate-600">·</span>
                  <span className="font-mono text-slate-400">درجة الثقة: {f.confidence}%</span>
                </div>
                <h3 className="mt-1 text-base font-semibold text-slate-100">{f.title}</h3>
                <div className="text-xs font-mono text-cyan-300 mt-0.5">
                  الأصل المتأثر: {f.assetName} · المسؤول: {f.owner} · الموعد النهائي: {f.remediationDeadline.slice(0, 10)}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <label htmlFor={`status-select-${f.id}`} className="text-xs text-slate-400">
                  الحالة:
                </label>
                <select
                  id={`status-select-${f.id}`}
                  value={f.status}
                  onChange={(e) => handleStatusChange(f.id, e.target.value)}
                  className="px-3 py-1.5 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                >
                  {Object.values(FindingStatus).map((st) => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
              <div className="p-3 bg-[#090D16] border border-slate-800/80 rounded">
                <div className="font-semibold text-slate-200 mb-1">
                  خطوات التحقق غير التدميري وإعادة الإنتاج
                </div>
                <div className="text-slate-400 whitespace-pre-line font-mono text-[11px]" dir="ltr">
                  {f.reproductionSteps}
                </div>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800/80 rounded">
                <div className="font-semibold text-emerald-300 mb-1">
                  خطة المعالجة والضوابط الدفاعية الموصى بها
                </div>
                <div className="text-slate-300">{f.remediationPlan}</div>
                <div className="mt-2 font-mono text-[11px] text-slate-500">
                  معرفات الأدلة المرتبطة: {f.evidenceIds.join(', ') || 'بانتظار إرفاق دليل التحقق'}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
