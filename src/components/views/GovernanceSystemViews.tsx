import React, { useState } from 'react';
import { apiClient, OverviewPayload, SessionPayload } from '../../api/client';
import { SecurityReport } from '../../domain/types';
import { SectionHeader } from '../SharedUI';

// ============================================================================
// 13. REPORTS AND EVIDENCE MANAGEMENT VIEW (التقارير والأدلة الرقمية)
// ============================================================================
export const ReportsEvidenceView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [reportType, setReportType] = useState<string>('EXECUTIVE_SUMMARY');
  const [reportTitle, setReportTitle] = useState('');
  const [selectedReportId, setSelectedReportId] = useState<string>(data.reports[0]?.id || '');
  const [generating, setGenerating] = useState(false);

  const selectedReport: SecurityReport | undefined =
    data.reports.find((r) => r.id === selectedReportId) ?? data.reports[0];

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    try {
      const created = await apiClient.generateReport({
        projectId: data.currentProject.id,
        reportType,
        title:
          reportTitle.trim() ||
          `تقرير ${reportType.replace(/_/g, ' ')} — ${data.currentProject.code}`,
      });
      setReportTitle('');
      setSelectedReportId(created.id);
      await onRefresh();
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadMarkdown = (rep: SecurityReport) => {
    const md = [
      `# ${rep.title}`,
      `**معرف التقرير:** ${rep.id} | **النوع:** ${rep.reportType} | **تاريخ التوليد:** ${rep.generatedAt}`,
      `**بواسطة:** ${rep.generatedBy} | **يتضمن بيانات محاكاة:** ${rep.includesSyntheticData ? 'نعم [SYNTHETIC_DEMO]' : 'لا'}`,
      `\n## النطاق والمنهجية`,
      rep.scopeSummary,
      rep.methodology,
      `\n## الملخص التنفيذي`,
      rep.executiveSummary,
      ...rep.sections.map((s) => `\n## ${s.heading}\n${s.content}`),
      `\n## القيود والملاحظات`,
      ...rep.limitations.map((l) => `- ${l}`),
    ].join('\n\n');

    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${rep.id}-${rep.reportType.toLowerCase()}.md`;
    a.click();
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="التقارير الأمنية وخزنة الأدلة الرقمية المشفرة"
        subtitle="إصدار تقارير رسمية مستندة إلى السجلات الفعلية المحفوظة مع فصل واضح بين الثغرات المؤكدة والفرضيات غير المؤكدة وتحديد بيانات المحاكاة."
      />

      <form
        onSubmit={handleGenerate}
        className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
      >
        <div>
          <label htmlFor="rep-type-select" className="block text-xs text-slate-400 mb-1">
            نوع قالب التقرير
          </label>
          <select
            id="rep-type-select"
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
          >
            <option value="EXECUTIVE_SUMMARY">ملخص أمني تنفيذي (EXECUTIVE_SUMMARY)</option>
            <option value="TECHNICAL_ASSESSMENT">تقرير تقييم تقني مفصل (TECHNICAL_ASSESSMENT)</option>
            <option value="VULNERABILITY_REGISTER">سجل الثغرات الكامل (VULNERABILITY_REGISTER)</option>
            <option value="ASSET_INVENTORY">تقرير جرد الأصول (ASSET_INVENTORY)</option>
            <option value="REMEDIATION_PLAN">خطة المعالجة والأولويات (REMEDIATION_PLAN)</option>
            <option value="INCIDENT_REPORT">تقرير استجابة للحوادث (INCIDENT_REPORT)</option>
            <option value="ATTACK_PATH_ANALYSIS">تحليل مسارات الهجوم (ATTACK_PATH_ANALYSIS)</option>
            <option value="LAB_EXERCISE_REPORT">تقرير تمارين المختبر (LAB_EXERCISE_REPORT)</option>
            <option value="AUDIT_COMPLIANCE">تقرير الامتثال والتدقيق (AUDIT_COMPLIANCE)</option>
          </select>
        </div>
        <div className="md:col-span-2">
          <label htmlFor="rep-title-input" className="block text-xs text-slate-400 mb-1">
            عنوان التقرير المخصص
          </label>
          <input
            id="rep-title-input"
            type="text"
            value={reportTitle}
            onChange={(e) => setReportTitle(e.target.value)}
            placeholder="مثال: التقرير الربعي لتقييم أمن البنية المصرفية"
            className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={generating}
          className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
        >
          {generating ? 'جارٍ إعداد التقرير...' : 'توليد تقرير موثق بالأدلة'}
        </button>
      </form>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 space-y-2">
          <h2 className="text-sm font-semibold text-slate-100">
            التقارير الصادرة ({data.reports.length})
          </h2>
          {data.reports.map((rep) => (
            <button
              key={rep.id}
              type="button"
              onClick={() => setSelectedReportId(rep.id)}
              className={`w-full text-right p-3.5 rounded-lg border transition-colors ${
                selectedReport?.id === rep.id
                  ? 'bg-cyan-950/30 border-cyan-500/50 text-slate-100'
                  : 'bg-[#0F1523] border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              <div className="text-xs font-mono text-cyan-300">{rep.reportType}</div>
              <div className="text-sm font-semibold mt-0.5">{rep.title}</div>
              <div className="text-[11px] font-mono text-slate-400 mt-1">
                المؤكدة: {rep.verifiedFindingsCount} · المرشحة: {rep.unverifiedHypothesesCount}
              </div>
            </button>
          ))}
        </div>

        <div className="lg:col-span-8 bg-[#0F1523] border border-slate-800/80 rounded-lg p-5 space-y-4">
          {selectedReport ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div>
                  <div className="text-xs font-mono text-slate-400">
                    {selectedReport.id} · صدر بتاريخ {selectedReport.generatedAt.slice(0, 19)} UTC بواسطة{' '}
                    {selectedReport.generatedBy}
                  </div>
                  <h3 className="text-lg font-semibold text-slate-100 mt-0.5">
                    {selectedReport.title}
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => handleDownloadMarkdown(selectedReport)}
                  className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
                >
                  تنزيل التقرير (.MD)
                </button>
              </div>

              <div className="text-xs text-slate-300 space-y-3">
                <div>
                  <span className="font-semibold text-slate-100">إقرار النطاق المصرح:</span>{' '}
                  {selectedReport.scopeSummary}
                </div>
                <div>
                  <span className="font-semibold text-slate-100">الملخص التنفيذي:</span>{' '}
                  {selectedReport.executiveSummary}
                </div>
                {selectedReport.sections.map((sec, i) => (
                  <div key={i} className="p-3 bg-[#090D16] border border-slate-800 rounded space-y-1">
                    <div className="font-semibold text-cyan-300">{sec.heading}</div>
                    <div className="whitespace-pre-line text-slate-300 font-mono text-[11px]">
                      {sec.content}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-xs text-slate-400">اختر تقريراً أو قم بتوليد تقرير جديد للمعاينة.</div>
          )}
        </div>
      </div>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-100">
          خزنة الأدلة الرقمية وبصمات SHA-256 ({data.evidence.length})
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {data.evidence.map((ev) => (
            <div
              key={ev.id}
              className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-2 text-xs"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="text-cyan-300 font-semibold" dir="ltr">{ev.id}</span>
                <span className="text-slate-400">
                  {ev.artifactType} · السجل المرتبط: {ev.linkedEntityId}
                </span>
              </div>
              <div className="font-semibold text-slate-100">{ev.title}</div>
              <div className="font-mono text-[11px] text-emerald-400 truncate" dir="ltr">
                SHA-256: {ev.sha256Digest}
              </div>
              <pre className="p-2.5 bg-[#090D16] border border-slate-800 rounded font-mono text-[11px] text-slate-300 overflow-x-auto text-left" dir="ltr">
                {ev.rawPayloadRedacted}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 14. INTEGRATIONS & SSRF-SAFE CONNECTION TESTING VIEW (التكاملات الخارجية)
// ============================================================================
export const IntegrationsView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [urlInputs, setUrlInputs] = useState<Record<string, string>>({});
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const handleTestConnection = async (intId: string, defaultUrl: string) => {
    setFeedback(null);
    const urlToTest = urlInputs[intId] ?? defaultUrl;
    try {
      const updated = await apiClient.testIntegration(intId, urlToTest);
      setFeedback({
        ok: true,
        text: `${updated.name}: ${updated.lastDiagnosticMessage}`,
      });
      await onRefresh();
    } catch (err: any) {
      setFeedback({ ok: false, text: `تم حظر الرابط بواسطة حماية SSRF: ${err.message}` });
      await onRefresh();
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="التكاملات الخارجية وبوابة الحماية من هجمات SSRF"
        subtitle="إدارة اتصال Gemini، MISP، SARIF، SIEM، ومزودي السحابة. يتم فحص جميع الروابط الصادرة على الخادم لمنع الوصول إلى عناوين Metadata (169.254.169.254) أو الشبكات الداخلية."
      />

      {feedback && (
        <div
          className={`p-3 rounded text-xs font-mono ${
            feedback.ok
              ? 'bg-emerald-950/40 border border-emerald-700 text-emerald-200'
              : 'bg-rose-950/40 border border-rose-700 text-rose-200'
          }`}
        >
          {feedback.text}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.integrations.map((int) => (
          <div
            key={int.id}
            className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3 text-xs"
          >
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-100">{int.name}</span>
              <span
                className={`font-mono font-semibold ${
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
            <div className="font-mono text-slate-400">
              الفئة: {int.category} · متغير البيئة السري: {int.secretEnvVarName} (
              {int.secretConfiguredInEnv ? 'متوفر في الخادم' : 'غير مضبوط في البيئة'})
            </div>
            <div className="text-slate-300">{int.lastDiagnosticMessage}</div>
            <div>
              <label htmlFor={`int-url-${int.id}`} className="block text-slate-400 mb-1">
                رابط الخدمة (محمي بفاحص SSRF على الخادم)
              </label>
              <div className="flex items-center gap-2">
                <input
                  id={`int-url-${int.id}`}
                  type="text"
                  dir="ltr"
                  value={urlInputs[int.id] ?? int.endpointUrl}
                  onChange={(e) =>
                    setUrlInputs((prev) => ({ ...prev, [int.id]: e.target.value }))
                  }
                  className="flex-1 px-3 py-1.5 font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
                <button
                  type="button"
                  onClick={() => handleTestConnection(int.id, int.endpointUrl)}
                  className="px-3 py-1.5 font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded whitespace-nowrap shrink-0"
                >
                  اختبار الاتصال
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 15. PLUGIN MARKETPLACE VIEW (متجر الإضافات)
// ============================================================================
export const PluginMarketplaceView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const handleToggle = async (pluginId: string, enabled: boolean) => {
    await apiClient.togglePlugin(pluginId, enabled);
    await onRefresh();
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="متجر الإضافات المعيارية وبيئة التشغيل المعزولة (Plugin Sandbox)"
        subtitle="إضافات معرفة بمواصفات صارمة (Typed Manifests) مع حدود للذاكرة والمهلة الزمنية والصلاحيات المطلوبة."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.plugins.map((plg) => (
          <div
            key={plg.id}
            className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3 text-xs"
          >
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {plg.name} <span className="font-mono text-slate-400">v{plg.version}</span>
                </h3>
                <div className="text-slate-400 font-mono text-[11px]">
                  المطور: {plg.author} · العزل: {plg.isolationMode}
                </div>
              </div>
              <button
                type="button"
                onClick={() => handleToggle(plg.id, !plg.enabled)}
                className={`px-3 py-1.5 font-medium rounded-md ${
                  plg.enabled
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-800 text-slate-300'
                }`}
              >
                {plg.enabled ? 'مفعّلة (اضغط للتعطيل)' : 'معطّلة (اضغط للتفعيل)'}
              </button>
            </div>
            <p className="text-slate-300">{plg.description}</p>
            <div className="font-mono text-[11px] text-slate-400">
              الصلاحيات: {plg.permissionsRequested.join(', ')} · المهلة: {plg.executionLimits.timeoutMs}ms · حد الذاكرة: {plg.executionLimits.memoryMb}MB
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// 16. TEAM AND ROLE-BASED ACCESS CONTROL (RBAC) VIEW (الفريق والصلاحيات)
// ============================================================================
export const TeamAccessControlView: React.FC<{
  data: OverviewPayload;
  session: SessionPayload | null;
  onSwitchUser: (userId: string) => Promise<void>;
}> = ({ data, session, onSwitchUser }) => {
  return (
    <div className="space-y-6">
      <SectionHeader
        title="إدارة الفريق والتحكم بالصلاحيات (RBAC) وعزل المشاريع"
        subtitle="7 أدوار وظيفية بأقل الصلاحيات اللازمة مطبقة على جميع مسارات الخادم. يمكنك تبديل جلسة المشغل أدناه لاختبار التحقق من الصلاحيات وعزل المشاريع."
      />

      <div className="bg-[#0F1523] border border-slate-800/80 rounded-lg overflow-x-auto">
        <table className="w-full text-right border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400">
              <th className="py-3 px-4">المشغل والبريد الإلكتروني</th>
              <th className="py-3 px-4">الدور الوظيفي (Role)</th>
              <th className="py-3 px-4">المشاريع المصرح بالوصول إليها</th>
              <th className="py-3 px-4">المصادقة متعددة العوامل والجلسات</th>
              <th className="py-3 px-4">تبديل الجلسة (للاختبار)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {data.users.map((u) => {
              const userMemberships = data.memberships.filter((m) => m.userId === u.id);
              const isCurrent = session?.user.id === u.id;
              return (
                <tr key={u.id} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-100">{u.displayName}</div>
                    <div className="font-mono text-slate-400" dir="ltr">{u.email}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-cyan-300">{u.role}</td>
                  <td className="py-3 px-4 font-mono text-slate-300" dir="ltr">
                    {userMemberships.map((m) => m.projectId).join(', ') || 'لا يوجد'}
                  </td>
                  <td className="py-3 px-4 font-mono text-emerald-400">
                    MFA مفعّل · {u.activeSessionCount} جلسة نشطة
                  </td>
                  <td className="py-3 px-4">
                    <button
                      type="button"
                      disabled={isCurrent}
                      onClick={() => onSwitchUser(u.id)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md ${
                        isCurrent
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          : 'bg-slate-800 text-slate-200 hover:bg-slate-700'
                      }`}
                    >
                      {isCurrent ? 'المشغل النشط حالياً' : 'التبديل إلى هذا المشغل'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ============================================================================
// 17. IMMUTABLE CRYPTOGRAPHIC AUDIT LOG VIEW (سجل التدقيق المشفر)
// ============================================================================
export const AuditLogView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const filtered = data.auditLog.filter(
    (a) => categoryFilter === 'ALL' || a.category === categoryFilter
  );

  return (
    <div className="space-y-6">
      <SectionHeader
        title="سجل التدقيق غير القابل للتعديل والمرتبط ببصمة SHA-256"
        subtitle="يتم توثيق كل تعديل في النطاق، إطلاق تقييم، رفض هدف خارج النطاق، أو منع صلاحيات RBAC ضمن سلسلة كتل مترابطة ببصمات SHA-256."
      />

      <div className="p-4 bg-[#0F1523] border border-emerald-500/40 rounded-lg flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="text-emerald-300">
          حالة سلسلة التجزئة (SHA-256 Chain): {data.auditVerification.valid ? 'موثقة وسليمة (لا يوجد تلاعب)' : 'تلاعب مكتشف'} · تم فحص {data.auditVerification.checkedCount} سجل متسلسل
        </div>
        <select
          aria-label="تصفية سجل التدقيق حسب الفئة"
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-3 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-200"
        >
          <option value="ALL">جميع فئات التدقيق</option>
          <option value="SCOPE">النطاق (SCOPE)</option>
          <option value="ASSESSMENT">التقييمات (ASSESSMENT)</option>
          <option value="FINDING">الثغرات (FINDING)</option>
          <option value="INCIDENT">الحوادث (INCIDENT)</option>
          <option value="RBAC">الصلاحيات (RBAC)</option>
          <option value="AI_COPILOT">المساعد الذكي (AI_COPILOT)</option>
          <option value="INTEGRATION">التكاملات (INTEGRATION)</option>
          <option value="EMERGENCY_STOP">الإيقاف الطارئ (EMERGENCY_STOP)</option>
        </select>
      </div>

      <div className="bg-[#0F1523] border border-slate-800/80 rounded-lg overflow-x-auto">
        <table className="w-full text-right border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] font-mono text-slate-400">
              <th className="py-3 px-4">التسلسل والتوقيت</th>
              <th className="py-3 px-4">الفاعل والدور</th>
              <th className="py-3 px-4">الفئة والعملية</th>
              <th className="py-3 px-4">النتيجة</th>
              <th className="py-3 px-4">التفاصيل وبصمة السلسلة SHA-256</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {filtered.map((entry) => (
              <tr key={entry.id} className="hover:bg-slate-800/30">
                <td className="py-3 px-4 font-mono" dir="ltr">
                  <div className="text-slate-200">#{entry.sequenceNumber}</div>
                  <div className="text-slate-500 text-[11px]">{entry.timestamp.slice(0, 19)}Z</div>
                </td>
                <td className="py-3 px-4">
                  <div className="font-mono text-slate-200" dir="ltr">{entry.actorEmail}</div>
                  <div className="font-mono text-[11px] text-slate-400">{entry.actorRole}</div>
                </td>
                <td className="py-3 px-4 font-mono">
                  <div className="text-cyan-300">{entry.action}</div>
                  <div className="text-slate-400 text-[11px]">
                    {entry.category} · الهدف: {entry.targetResource}
                  </div>
                </td>
                <td className="py-3 px-4 font-mono">
                  <span
                    className={
                      entry.outcome === 'ALLOWED'
                        ? 'text-emerald-400'
                        : 'text-rose-400 font-semibold'
                    }
                  >
                    {entry.outcome}
                  </span>
                </td>
                <td className="py-3 px-4 max-w-md">
                  <div className="text-slate-200 leading-relaxed break-words">{entry.details}</div>
                  <div className="font-mono text-[10px] text-slate-500 mt-0.5 truncate" dir="ltr">
                    SHA-256: {entry.entryHash.slice(0, 32)}... (Prev: {entry.prevHash.slice(0, 14)}...)
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
// 18. SYSTEM HEALTH & OBSERVABILITY VIEW (صحة النظام والمراقبة)
// ============================================================================
export const SystemHealthView: React.FC<{ data: OverviewPayload }> = ({ data }) => {
  return (
    <div className="space-y-6">
      <SectionHeader
        title="مراقبة صحة النظام والحصص التشغيلية وضوابط الأمان"
        subtitle="الحالة الفورية لطابور مهام التقييم، قاعدة البيانات الدائمة، محددات معدل الطلبات، وضوابط الحماية الإلزامية."
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-1">
          <div className="text-xs text-slate-400">التحقق الإلزامي من النطاق على الخادم</div>
          <div className="text-lg font-mono font-semibold text-emerald-400">مفعّل وإلزامي</div>
          <div className="text-xs text-slate-400">
            يتم فحص كل طلب تقييم مقابل النطاقات وعناوين CIDR وقائمة المستثنيات قبل التنفيذ.
          </div>
        </div>
        <div className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-1">
          <div className="text-xs text-slate-400">الحماية من هجمات SSRF وعناوين Metadata</div>
          <div className="text-lg font-mono font-semibold text-emerald-400">مفعّل بالكامل</div>
          <div className="text-xs text-slate-400">
            حظر تلقائي لعناوين 169.254.169.254 و localhost والشبكات الخاصة غير المصرحة.
          </div>
        </div>
        <div className="p-4 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-1">
          <div className="text-xs text-slate-400">حالة مفتاح الإيقاف الطارئ الشامل</div>
          <div
            className={`text-lg font-mono font-semibold ${
              data.emergencyStopActive ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {data.emergencyStopActive ? 'متوقف طارئاً (HALTED)' : 'تشغيل طبيعي (NOMINAL)'}
          </div>
          <div className="text-xs text-slate-400">
            مفتاح إيقاف فوري لجميع مهام التقييم الجارية أو المنتظرة في الطابور.
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// 19. SETTINGS, PROJECT CREATION & SYNTHETIC DATASET MANAGEMENT VIEW (الإعدادات)
// ============================================================================
export const SettingsView: React.FC<{
  data: OverviewPayload;
  onRefresh: () => Promise<void>;
}> = ({ data, onRefresh }) => {
  const [projName, setProjName] = useState('');
  const [projCode, setProjCode] = useState('');
  const [projDesc, setProjDesc] = useState('');
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projName.trim() || !projCode.trim()) return;
    try {
      const created = await apiClient.createProject({
        name: projName.trim(),
        code: projCode.trim(),
        description: projDesc.trim(),
      });
      setProjName('');
      setProjCode('');
      setProjDesc('');
      setStatusMsg(`تم إنشاء المشروع "${created.name}" (${created.code}) بنطاق وصلاحيات معزولة.`);
      await onRefresh();
    } catch (err: any) {
      setStatusMsg(`خطأ: ${err.message}`);
    }
  };

  const handleToggleSynthetic = async (includeSynthetic: boolean) => {
    try {
      await apiClient.toggleSyntheticData(includeSynthetic);
      setStatusMsg(
        includeSynthetic
          ? 'تمت استعادة حزمة بيانات المحاكاة التجريبية الموسومة.'
          : 'تم حذف سجلات المحاكاة التجريبية من العرض النشط.'
      );
      await onRefresh();
    } catch (err: any) {
      setStatusMsg(`خطأ: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="إعدادات مساحة العمل وإنشاء المشاريع وإدارة بيانات المحاكاة"
        subtitle="إنشاء مشاريع تقييم أمني معزولة الصلاحيات والتحكم في حزمة بيانات المحاكاة التجريبية."
      />

      {statusMsg && (
        <div className="p-3 bg-[#0F1523] border border-cyan-500/40 rounded text-xs text-cyan-200">
          {statusMsg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form
          onSubmit={handleCreateProject}
          className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-3"
        >
          <h2 className="text-sm font-semibold text-slate-100">
            إنشاء مشروع تقييم أمني جديد (معزول الصلاحيات)
          </h2>
          <div>
            <label htmlFor="set-proj-name" className="block text-xs text-slate-400 mb-1">
              اسم المشروع
            </label>
            <input
              id="set-proj-name"
              type="text"
              value={projName}
              onChange={(e) => setProjName(e.target.value)}
              placeholder="مثال: تقييم أمن واجهات الخدمات المصرفية للهاتف"
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="set-proj-code" className="block text-xs text-slate-400 mb-1">
              رمز المشروع (Code)
            </label>
            <input
              id="set-proj-code"
              type="text"
              dir="ltr"
              value={projCode}
              onChange={(e) => setProjCode(e.target.value)}
              placeholder="BNX-2026-MOB"
              className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <div>
            <label htmlFor="set-proj-desc" className="block text-xs text-slate-400 mb-1">
              وصف النطاق والأهداف
            </label>
            <input
              id="set-proj-desc"
              type="text"
              value={projDesc}
              onChange={(e) => setProjDesc(e.target.value)}
              placeholder="مراجعة أمنية ربع سنوية مصرح بها..."
              className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md"
          >
            إنشاء المشروع والنطاق الأساسي
          </button>
        </form>

        <div className="p-5 bg-[#0F1523] border border-slate-800/80 rounded-lg space-y-4">
          <h2 className="text-sm font-semibold text-slate-100">
            إدارة بيانات المحاكاة التجريبية (Synthetic Demonstration Dataset)
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            تتضمن منصة بارون نيكسوس حزمة بيانات محاكاة موسومة بوضوح (<code className="text-cyan-300">SYNTHETIC_DEMO</code>) لتمكين استعراض مخططات الهجوم وتنبيهات SOC وسلاسل الأدلة دون ادعاء تنفيذ فحوصات خارجية حية غير مصرحة. يمكنك حذف هذه البيانات أو استعادتها في أي وقت.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => handleToggleSynthetic(true)}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-md"
            >
              استعادة بيانات المحاكاة التجريبية
            </button>
            <button
              type="button"
              onClick={() => handleToggleSynthetic(false)}
              className="px-4 py-2 text-xs font-medium text-rose-200 bg-rose-950/50 border border-rose-800 hover:bg-rose-900/60 rounded-md"
            >
              حذف جميع سجلات المحاكاة
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
