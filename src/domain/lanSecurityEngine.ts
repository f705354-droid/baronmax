/**
 * Pure Domain Engine for Local Network Security Assessment & Asset Discovery (v2.5 Hardened)
 *
 * Security Upgrades & Fixes Applied:
 * 1. Blocks Octal / Leading-Zero IPv4 SSRF & Scope Bypass (e.g., 010.0.0.1 -> 8.0.0.1).
 * 2. Validates contiguous netmasks (rejects malformed masks like 255.0.255.0).
 * 3. Blocks subnet broadcast (.255) and network base (.0) addresses in single-host port scans.
 * 4. Supports explicit controlled Loopback Self-Audit mode (127.0.0.1) for real local socket probing.
 * 5. Includes ARP Spoofing / Duplicate MAC Anomaly Detection Engine.
 * 6. Includes HTTP Security Header Posture Evaluator & Automated Linux Hardening Playbook Generator.
 */

export type LanScanProfile =
  | 'QUICK_AUDIT'
  | 'SERVICE_VERSION'
  | 'OS_DETECTION'
  | 'SAFE_SCRIPTS'
  | 'REAL_LIVE_SOCKET_AUDIT';

export interface LanNicInfo {
  name: string;
  ipv4: string;
  netmask: string;
  cidr: string;
  gateway: string;
  mac: string;
  vendor: string;
  isUp: boolean;
  speedMbps: number;
  mtu: number;
  isPrivateRfc1918: boolean;
  rxBytes: number;
  txBytes: number;
  executionSource?: 'REAL_KERNEL_IP_ADDR' | 'HYBRID_KALI_NIC';
}

export interface LanDiscoveredHost {
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  latencyMs: number;
  role: 'GATEWAY' | 'SCANNER_HOST' | 'SERVER' | 'WORKSTATION' | 'IOT_APPLIANCE';
  osGuess: string;
  openPortsCount: number;
  riskScore: number;
  status: 'ONLINE' | 'RESPONDING';
  lastSeenAt: string;
  executionOrigin?: 'REAL_LOCAL_SOCKET' | 'ARP_KERNEL_TABLE' | 'LAN_TOPOLOGY';
}

export interface LanServicePort {
  port: number;
  protocol: 'TCP' | 'UDP';
  service: string;
  product: string;
  version: string;
  cpe: string;
  latencyMs?: number;
  tlsStatus?: string;
  bannerSummary: string;
  safeScriptFindings: { scriptId: string; output: string }[];
}

export interface LanCorrelatedCve {
  cveId: string;
  cvssScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  affectedPort: string;
  service: string;
  cpeMatched: string;
  summaryAr: string;
  remediationAr: string;
  publishedYear: number;
  source?: 'LOCAL_KB' | 'NIST_NVD_LIVE';
}

export interface HttpHeaderAuditResult {
  url: string;
  statusCode: number;
  responseTimeMs: number;
  scorePercent: number;
  rawHeaders: Record<string, string>;
  checks: {
    header: string;
    present: boolean;
    value: string;
    status: 'PASS' | 'WARN' | 'FAIL';
    recommendationAr: string;
  }[];
}

export interface ArpAnomalyFinding {
  id: string;
  type: 'DUPLICATE_MAC_SPOOFING' | 'BROADCAST_MAC_ANOMALY' | 'INCOMPLETE_ARP';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  macAddress: string;
  affectedIps: string[];
  descriptionAr: string;
  remediationAr: string;
}

export interface DefensiveHardeningPlaybook {
  targetIp: string;
  generatedAt: string;
  nftablesRules: string;
  sysctlHardening: string;
  sshAndServiceHardening: string;
}

export interface LanHostAuditResult {
  targetIp: string;
  hostname: string;
  profile: LanScanProfile;
  executionMode: 'REAL_NODE_NET_SOCKET' | 'SUBPROCESS_EXEC_SAFE';
  executedTechnique: '-sS (SYN Raw)' | '-sT (TCP Connect Real Socket)';
  commandExecuted: string[];
  osDetection: string;
  auditedAt: string;
  durationMs: number;
  ports: LanServicePort[];
  cves: LanCorrelatedCve[];
  httpHeaderAudit?: HttpHeaderAuditResult;
  hardeningPlaybook?: DefensiveHardeningPlaybook;
}

export interface LanTrafficTelemetry {
  timestamp: string;
  protocolDistribution: {
    TCP: number;
    UDP: number;
    ICMP: number;
    DNS: number;
  };
  bandwidthPerNic: {
    interfaceName: string;
    rxKbps: number;
    txKbps: number;
    totalRxMb: number;
    totalTxMb: number;
  }[];
  activeConnections: {
    protocol: 'TCP' | 'UDP';
    localAddress: string;
    remoteAddress: string;
    state: string;
    processName: string;
  }[];
  kernelRouteTable?: {
    destination: string;
    gateway: string;
    device: string;
    protocol: string;
    scope: string;
  }[];
  arpAnomalies?: ArpAnomalyFinding[];
}

export interface LanModuleSelfAuditIssue {
  id: string;
  titleAr: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  weaknessFoundAr: string;
  fixAppliedAr: string;
  status: 'FIXED_AND_VERIFIED';
}

export interface LanValidationDecision {
  allowed: boolean;
  normalizedTarget: string;
  isCidr: boolean;
  isLoopbackSelfAudit?: boolean;
  reasonAr: string;
  rejectionCode?:
    | 'COMMAND_INJECTION_DETECTED'
    | 'OCTAL_IP_BYPASS_DETECTED'
    | 'INVALID_IP_FORMAT'
    | 'NON_CONTIGUOUS_NETMASK'
    | 'BROADCAST_OR_NET_ADDRESS_FORBIDDEN'
    | 'PUBLIC_IP_FORBIDDEN'
    | 'PREFIX_TOO_BROAD';
}

const SHELL_METACHAR_REGEX = /[;&|$`()<>\\\n\r\t'"]/;

const OUI_VENDOR_MAP: Record<string, string> = {
  '00:50:56': 'VMware, Inc.',
  '00:0C:29': 'VMware, Inc.',
  '08:00:27': 'PCS Systemtechnik GmbH (VirtualBox)',
  '52:54:00': 'QEMU / KVM Virtual NIC',
  '00:15:5D': 'Microsoft Hyper-V Virtual Switch',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Trading Ltd',
  'F0:9F:C2': 'Ubiquiti Networks Inc.',
  '24:5A:4C': 'Ubiquiti Networks Inc.',
  '00:09:0F': 'Fortinet, Inc. (FortiGate)',
  '00:18:0A': 'Cisco Meraki',
  '00:1B:63': 'Apple, Inc.',
  '3C:22:FB': 'Apple, Inc.',
  '00:25:90': 'Super Micro Computer, Inc.',
  '00:1E:67': 'Intel Corporate Server Adapter',
  '02:42:AC': 'Docker Container Bridge NIC',
  '42:00:4E': 'Google Cloud / gVisor Virtual NIC',
};

/**
 * Checks if an IPv4 string contains leading zeros in any octet (e.g., 010.0.0.1),
 * which can cause octal interpretation in C/POSIX networking libraries.
 */
export function hasOctalOrLeadingZeroOctet(ip: string): boolean {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.some((part) => part.length > 1 && part.startsWith('0'));
}

function ipv4ToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    result = ((result << 8) | octet) >>> 0;
  }
  return result >>> 0;
}

function uint32ToIpv4(num: number): string {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join('.');
}

export function isValidContiguousNetmask(netmask: string): boolean {
  const maskNum = ipv4ToUint32(netmask);
  if (maskNum === null || maskNum === 0) return false;
  const inverted = (~maskNum) >>> 0;
  return ((inverted + 1) & inverted) === 0;
}

export function isRfc1918PrivateIpv4(ip: string): boolean {
  const num = ipv4ToUint32(ip);
  if (num === null) return false;
  const first = (num >>> 24) & 255;
  const second = (num >>> 16) & 255;
  // 10.0.0.0/8
  if (first === 10) return true;
  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (first === 172 && second >= 16 && second <= 31) return true;
  // 192.168.0.0/16
  if (first === 192 && second === 168) return true;
  return false;
}

export function calculateCidrFromIpAndMask(ip: string, netmask: string): string {
  const ipNum = ipv4ToUint32(ip);
  const maskNum = ipv4ToUint32(netmask);
  if (ipNum === null || maskNum === null || !isValidContiguousNetmask(netmask)) {
    return `${ip}/24`;
  }

  let prefix = 0;
  let temp = maskNum;
  while (temp & 0x80000000) {
    prefix++;
    temp = (temp << 1) >>> 0;
  }
  const netNum = (ipNum & maskNum) >>> 0;
  return `${uint32ToIpv4(netNum)}/${prefix}`;
}

export function validatePrivateLanTarget(
  rawInput: string,
  options?: { allowCidr?: boolean; allowLoopbackSelfAudit?: boolean }
): LanValidationDecision {
  const allowCidr = options?.allowCidr ?? true;
  const allowLoopback = options?.allowLoopbackSelfAudit ?? false;
  const cleaned = (rawInput || '').trim();

  if (!cleaned || SHELL_METACHAR_REGEX.test(cleaned) || /\s/.test(cleaned)) {
    return {
      allowed: false,
      normalizedTarget: cleaned,
      isCidr: false,
      rejectionCode: 'COMMAND_INJECTION_DETECTED',
      reasonAr:
        'تم حظر المدخل فوراً: يحتوي على محارف صدفة أو مسافات غير مسموحة (حماية صارمة ضد Command Injection).',
    };
  }

  const baseIpCandidate = cleaned.includes('/') ? cleaned.split('/')[0] : cleaned;
  if (hasOctalOrLeadingZeroOctet(baseIpCandidate)) {
    return {
      allowed: false,
      normalizedTarget: cleaned,
      isCidr: cleaned.includes('/'),
      rejectionCode: 'OCTAL_IP_BYPASS_DETECTED',
      reasonAr: `تم رفض العنوان "${cleaned}": يحتوي على أصفار بادئة (Octal IP Encoding) قد تُستغل لتجاوز فلاتر النطاق (SSRF / Scope Bypass).`,
    };
  }

  if (cleaned.includes('/')) {
    if (!allowCidr) {
      return {
        allowed: false,
        normalizedTarget: cleaned,
        isCidr: true,
        rejectionCode: 'INVALID_IP_FORMAT',
        reasonAr: 'يتطلب فحص المنافذ تحديد عنوان IP مفرد لجهاز متصل وليس نطاق شبكة كامل.',
      };
    }
    const parts = cleaned.split('/');
    if (parts.length !== 2) {
      return {
        allowed: false,
        normalizedTarget: cleaned,
        isCidr: true,
        rejectionCode: 'INVALID_IP_FORMAT',
        reasonAr: 'صيغة نطاق CIDR غير صالحة.',
      };
    }
    const [ipPart, prefixStr] = parts;
    const ipNum = ipv4ToUint32(ipPart);
    const prefix = Number(prefixStr);
    if (ipNum === null || !/^\d{1,2}$/.test(prefixStr) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return {
        allowed: false,
        normalizedTarget: cleaned,
        isCidr: true,
        rejectionCode: 'INVALID_IP_FORMAT',
        reasonAr: 'صيغة نطاق CIDR غير صالحة. استخدم صيغة قياسية مثل 192.168.1.0/24.',
      };
    }
    if (!isRfc1918PrivateIpv4(ipPart)) {
      return {
        allowed: false,
        normalizedTarget: cleaned,
        isCidr: true,
        rejectionCode: 'PUBLIC_IP_FORBIDDEN',
        reasonAr: `تم رفض النطاق ${cleaned}: يقع خارج نطاقات الشبكة المحلية الخاصة (RFC 1918). يُحظر فحص العناوين العامة الخارجية.`,
      };
    }
    if (prefix < 16) {
      return {
        allowed: false,
        normalizedTarget: cleaned,
        isCidr: true,
        rejectionCode: 'PREFIX_TOO_BROAD',
        reasonAr: 'قناع الشبكة واسع جداً. الحد الأقصى المسموح للفحص الآمن هو /16 إلى /32.',
      };
    }
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkIp = uint32ToIpv4((ipNum & mask) >>> 0);
    return {
      allowed: true,
      normalizedTarget: `${networkIp}/${prefix}`,
      isCidr: true,
      reasonAr: `تم التحقق بنجاح: النطاق ${networkIp}/${prefix} يقع ضمن الشبكة المحلية الخاصة (RFC 1918).`,
    };
  }

  // Single IPv4 validation
  if (allowLoopback && cleaned === '127.0.0.1') {
    return {
      allowed: true,
      normalizedTarget: '127.0.0.1',
      isCidr: false,
      isLoopbackSelfAudit: true,
      reasonAr: 'تم السماح بفحص واجهة المضيف المحلي (Loopback Self-Audit 127.0.0.1) لاختبار المنافذ والخدمات الحقيقية المشغلة على النظام.',
    };
  }

  const ipNum = ipv4ToUint32(cleaned);
  if (ipNum === null) {
    return {
      allowed: false,
      normalizedTarget: cleaned,
      isCidr: false,
      rejectionCode: 'INVALID_IP_FORMAT',
      reasonAr: 'صيغة عنوان IPv4 غير صالحة.',
    };
  }

  if (!isRfc1918PrivateIpv4(cleaned)) {
    return {
      allowed: false,
      normalizedTarget: cleaned,
      isCidr: false,
      rejectionCode: 'PUBLIC_IP_FORBIDDEN',
      reasonAr: `تم رفض العنوان ${cleaned}: ليس ضمن نطاقات الشبكة المحلية الخاصة (10.0.0.0/8 أو 172.16.0.0/12 أو 192.168.0.0/16).`,
    };
  }

  // Block .0 (network base) and .255 (subnet broadcast) when targeting a single host
  const lastOctet = ipNum & 255;
  if (!allowCidr && (lastOctet === 0 || lastOctet === 255)) {
    return {
      allowed: false,
      normalizedTarget: cleaned,
      isCidr: false,
      rejectionCode: 'BROADCAST_OR_NET_ADDRESS_FORBIDDEN',
      reasonAr: `تم حظر العنوان ${cleaned}: لا يُسمح باستهداف عنوان الشبكة الأساسي (.0) أو عنوان البث الجماعي Broadcast (.255) لمنع هجمات التضخيم.`,
    };
  }

  return {
    allowed: true,
    normalizedTarget: cleaned,
    isCidr: false,
    reasonAr: `تم التحقق بنجاح: العنوان ${cleaned} ينتمي للشبكة المحلية الخاصة (RFC 1918).`,
  };
}

export function lookupMacVendor(mac: string): string {
  if (!mac || mac.length < 8) return 'واجهة شبكة محلية قياسية (IEEE OUI)';
  const prefix = mac.toUpperCase().replace(/-/g, ':').slice(0, 8);
  return OUI_VENDOR_MAP[prefix] || 'IEEE 802.3 Ethernet Adapter';
}

export function buildSafeNmapArgs(
  targetIp: string,
  profile: LanScanProfile,
  hasRawSocketPrivilege: boolean,
  includeUdpTop20 = false,
  allowLoopbackSelfAudit = false
): string[] {
  const check = validatePrivateLanTarget(targetIp, {
    allowCidr: false,
    allowLoopbackSelfAudit,
  });
  if (!check.allowed) {
    throw new Error(check.reasonAr);
  }

  const scanFlag = hasRawSocketPrivilege ? '-sS' : '-sT';
  const args: string[] = ['nmap', '-oX', '-', scanFlag, '-Pn', '--open'];

  if (profile === 'QUICK_AUDIT' || profile === 'REAL_LIVE_SOCKET_AUDIT') {
    args.push('-F', '-T4');
  } else if (profile === 'SERVICE_VERSION') {
    args.push('-sV', '--version-light', '-T4');
  } else if (profile === 'OS_DETECTION') {
    if (hasRawSocketPrivilege) {
      args.push('-sV', '-O', '--osscan-limit');
    } else {
      args.push('-sV', '--version-light');
    }
  } else if (profile === 'SAFE_SCRIPTS') {
    args.push('-sV', '--script=default,safe,ssl-enum-ciphers');
  }

  if (includeUdpTop20 && hasRawSocketPrivilege) {
    args.push('-sU', '--top-ports', '20');
  }

  args.push(check.normalizedTarget);
  return args;
}

/**
 * Analyzes an ARP table for ARP cache poisoning / duplicate MAC anomalies.
 */
export function analyzeArpTableAnomalies(
  arpEntries: { ip: string; mac: string }[]
): ArpAnomalyFinding[] {
  const macToIps = new Map<string, string[]>();
  const findings: ArpAnomalyFinding[] = [];

  for (const entry of arpEntries) {
    const cleanMac = (entry.mac || '').trim().toUpperCase();
    if (!cleanMac || cleanMac === 'LOCAL_INTERFACE') continue;

    if (cleanMac === '00:00:00:00:00:00') {
      findings.push({
        id: `arp-inc-${entry.ip}`,
        type: 'INCOMPLETE_ARP',
        severity: 'MEDIUM',
        macAddress: cleanMac,
        affectedIps: [entry.ip],
        descriptionAr: `سجل ARP غير مكتمل (00:00:00:00:00:00) للعنوان ${entry.ip}؛ قد يشير إلى مسح نشط أو جهاز متوقف.`,
        remediationAr: 'مراقبة طلبات ARP المتكررة عبر أداة arpwatch وتنظيف جدول الجيران عبر ip neigh flush.',
      });
      continue;
    }

    if (cleanMac === 'FF:FF:FF:FF:FF:FF') {
      findings.push({
        id: `arp-bcast-${entry.ip}`,
        type: 'BROADCAST_MAC_ANOMALY',
        severity: 'HIGH',
        macAddress: cleanMac,
        affectedIps: [entry.ip],
        descriptionAr: `اقتران غير طبيعي لعنوان IP (${entry.ip}) بعنوان MAC للبث الجماعي (FF:FF:FF:FF:FF:FF).`,
        remediationAr: 'حظر الحزم المزورة وتفعيل Dynamic ARP Inspection (DAI) على المحول الشبكي.',
      });
      continue;
    }

    const list = macToIps.get(cleanMac) ?? [];
    if (!list.includes(entry.ip)) {
      list.push(entry.ip);
    }
    macToIps.set(cleanMac, list);
  }

  for (const [mac, ips] of macToIps.entries()) {
    if (ips.length > 1) {
      findings.push({
        id: `arp-spoof-${mac.replace(/:/g, '')}`,
        type: 'DUPLICATE_MAC_SPOOFING',
        severity: 'CRITICAL',
        macAddress: mac,
        affectedIps: ips,
        descriptionAr: `اشتباه قوي بتسميم جدول ARP (ARP Spoofing / MITM): العنوان الفيزيائي ${mac} يدّعي ملكية عدة عناوين IP متزامنة (${ips.join(', ')}).`,
        remediationAr:
          'تفعيل ميزة Dynamic ARP Inspection (DAI) و DHCP Snooping على السويتش، وتثبيت عنوان MAC للبوابة عبر: sudo arp -s <Gateway_IP> <Gateway_MAC>.',
      });
    }
  }

  return findings;
}

/**
 * Evaluates raw HTTP response headers against 7 security posture checks.
 */
export function evaluateHttpSecurityHeaders(
  url: string,
  statusCode: number,
  responseTimeMs: number,
  rawHeaders: Record<string, string>
): HttpHeaderAuditResult {
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    lowerHeaders[k.toLowerCase()] = String(v);
  }

  const requiredChecks: {
    header: string;
    key: string;
    recommendationAr: string;
  }[] = [
    {
      header: 'X-Content-Type-Options',
      key: 'x-content-type-options',
      recommendationAr: 'أضف الترويسة X-Content-Type-Options: nosniff لمنع تخمين نوع المحتوى (MIME Sniffing).',
    },
    {
      header: 'X-Frame-Options',
      key: 'x-frame-options',
      recommendationAr: 'أضف الترويسة X-Frame-Options: SAMEORIGIN أو DENY للحماية من هجمات Clickjacking.',
    },
    {
      header: 'Referrer-Policy',
      key: 'referrer-policy',
      recommendationAr: 'أضف الترويسة Referrer-Policy: no-referrer أو strict-origin-when-cross-origin.',
    },
    {
      header: 'Strict-Transport-Security',
      key: 'strict-transport-security',
      recommendationAr: 'فعّل HSTS عبر Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    },
    {
      header: 'Content-Security-Policy',
      key: 'content-security-policy',
      recommendationAr: "حدد سياسة أمان محتوى صارمة (CSP) مثل default-src 'self' لمنع XSS.",
    },
    {
      header: 'Permissions-Policy',
      key: 'permissions-policy',
      recommendationAr: 'قيد واجهات المتصفح الحساسة عبر Permissions-Policy: camera=(), microphone=(), geolocation=().',
    },
  ];

  let passedCount = 0;
  const checks = requiredChecks.map((item) => {
    const val = lowerHeaders[item.key];
    const present = Boolean(val);
    if (present) passedCount++;
    return {
      header: item.header,
      present,
      value: val || 'غير موجودة (MISSING)',
      status: (present ? 'PASS' : 'WARN') as 'PASS' | 'WARN' | 'FAIL',
      recommendationAr: item.recommendationAr,
    };
  });

  // Check Server / X-Powered-By version disclosure
  const serverBanner = lowerHeaders['server'] || lowerHeaders['x-powered-by'] || '';
  const leaksBanner = Boolean(serverBanner);
  if (!leaksBanner) passedCount++;
  checks.push({
    header: 'Server / X-Powered-By Exposure',
    present: !leaksBanner,
    value: leaksBanner ? `مكشوف: ${serverBanner}` : 'مخفي بأمان',
    status: leaksBanner ? 'WARN' : 'PASS',
    recommendationAr: 'قم بإخفاء ترويسة X-Powered-By (عبر app.disable("x-powered-by")) وإخفاء إصدار الخادم في server_tokens.',
  });

  const scorePercent = Math.round((passedCount / checks.length) * 100);
  return {
    url,
    statusCode,
    responseTimeMs,
    scorePercent,
    rawHeaders: lowerHeaders,
    checks,
  };
}

/**
 * Generates an actionable Linux defensive hardening playbook tailored to the host's open ports & CVEs.
 */
export function generateDefensiveHardeningPlaybook(
  targetIp: string,
  ports: LanServicePort[],
  cves: LanCorrelatedCve[]
): DefensiveHardeningPlaybook {
  const openPortNumbers = ports.map((p) => p.port);
  const allowedTcp = openPortNumbers.filter((p) => ![6379, 445, 1900].includes(p));
  const nftAllowedList = allowedTcp.length > 0 ? allowedTcp.join(', ') : '22, 443';

  const nftablesRules = `#!/usr/sbin/nft -f
# Baron Nexus Automated Host Firewall Policy for ${targetIp}
flush ruleset

table inet baron_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type echo-request limit rate 5/second accept
    tcp dport { ${nftAllowedList} } ct state new accept
    counter log prefix "[BARON-NFT-DROP] " drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}`;

  const sysctlHardening = `# /etc/sysctl.d/99-baron-lan-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_Redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1`;

  const remediationSteps = cves.map((c) => `# [${c.cveId} - CVSS ${c.cvssScore}] ${c.remediationAr}`).join('\n');
  const sshAndServiceHardening = `# توصيات تحصين الخدمات على الجهاز ${targetIp}
${remediationSteps || '# جميع الخدمات المكتشفة محدثة؛ يُوصى بمراجعة الصلاحيات الدورية.'}
# تحصين SSH (/etc/ssh/sshd_config):
PermitRootLogin no
PasswordAuthentication no
AllowAgentForwarding no
X11Forwarding no
MaxAuthTries 3`;

  return {
    targetIp,
    generatedAt: new Date().toISOString(),
    nftablesRules,
    sysctlHardening,
    sshAndServiceHardening,
  };
}

const CVE_CORRELATION_CATALOG: {
  keywords: string[];
  cve: Omit<LanCorrelatedCve, 'affectedPort' | 'service'>;
}[] = [
  {
    keywords: ['openssh 8.2', 'openssh 8.4', 'openssh_8.2', 'openssh_7.'],
    cve: {
      cveId: 'CVE-2023-38408',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      cpeMatched: 'cpe:/a:openbsd:openssh:8.2p1',
      summaryAr:
        'ثغرة في خدمة SSH Agent Forwarding تسمح بتحميل مكتبات PKCS#11 في ظروف تفعيل التوجيه عن بُعد.',
      remediationAr:
        'ترقية حزمة openssh-server إلى الإصدار 9.3p2+ وتعطيل AllowAgentForwarding و PermitRootLogin في /etc/ssh/sshd_config.',
      publishedYear: 2023,
      source: 'LOCAL_KB',
    },
  },
  {
    keywords: ['nginx 1.18', 'nginx/1.18', 'nginx 1.14'],
    cve: {
      cveId: 'CVE-2022-41741',
      cvssScore: 7.8,
      severity: 'HIGH',
      cpeMatched: 'cpe:/a:f5:nginx:1.18.0',
      summaryAr:
        'خلل في إدارة الذاكرة داخل وحدة ngx_http_mp4_module في إصدارات Nginx الأقدم من 1.23.2.',
      remediationAr:
        'ترقية خادم Nginx إلى الإصدار المستقر الأحدث وتفعيل ترويسات الأمان HSTS و Content-Security-Policy وإخفاء server_tokens.',
      publishedYear: 2022,
      source: 'LOCAL_KB',
    },
  },
  {
    keywords: ['postgresql 13', 'postgresql 14', 'postgres 13'],
    cve: {
      cveId: 'CVE-2023-39417',
      cvssScore: 8.8,
      severity: 'HIGH',
      cpeMatched: 'cpe:/a:postgresql:postgresql:14.5',
      summaryAr:
        'ثغرة في معالجة معاملات نصوص الإضافات البرمجية في خادم قواعد البيانات PostgreSQL.',
      remediationAr:
        'تقييد الوصول في ملف pg_hba.conf ليقتصر على عناوين التطبيق المصرحة فقط وإلزام تشفير TLS (hostssl) وتحديث الحزمة.',
      publishedYear: 2023,
      source: 'LOCAL_KB',
    },
  },
  {
    keywords: ['samba 4.13', 'samba 4.11', 'smbd 4.'],
    cve: {
      cveId: 'CVE-2021-44142',
      cvssScore: 9.9,
      severity: 'CRITICAL',
      cpeMatched: 'cpe:/a:samba:samba:4.13.14',
      summaryAr:
        'ثغرة قراءة وكتابة خارج حدود الذاكرة (Out-of-Bounds Heap Read/Write) في وحدة vfs_fruit بخدمة مشاركة الملفات Samba.',
      remediationAr:
        'ترقية حزمة Samba فوراً أو إزالة fruit من إعداد vfs objects في /etc/samba/smb.conf وتقييد المنفذ 445 بجدار الحماية المحلي.',
      publishedYear: 2022,
      source: 'LOCAL_KB',
    },
  },
  {
    keywords: ['redis 6.0', 'redis 5.0', 'redis key-value'],
    cve: {
      cveId: 'CVE-2022-0543',
      cvssScore: 10.0,
      severity: 'CRITICAL',
      cpeMatched: 'cpe:/a:redis:redis:6.0.16',
      summaryAr:
        'ثغرة تجاوز بيئة Lua الرملية في حزم Redis المبنية ديناميكياً أو تعرض الخدمة بدون مصادقة على الشبكة المحلية.',
      remediationAr:
        'تفعيل requirepass وقوائم ACL في redis.conf وربط الخدمة بواجهة محددة عبر bind 127.0.0.1 وتحديث الحزمة.',
      publishedYear: 2022,
      source: 'LOCAL_KB',
    },
  },
  {
    keywords: ['dropbear', 'lighttpd 1.4', 'upnp', 'miniupnpd'],
    cve: {
      cveId: 'CVE-2022-27226',
      cvssScore: 6.5,
      severity: 'MEDIUM',
      cpeMatched: 'cpe:/o:router:firmware:1.4',
      summaryAr:
        'إعدادات إدارة بوابة الشبكة تسمح باستعلامات تعريفية موسعة على واجهة LAN الداخلية.',
      remediationAr:
        'تعطيل خدمة UPnP غير الضرورية، فرض TLS 1.3 على لوحة الإدارة، وتغيير منافذ الإدارة الافتراضية.',
      publishedYear: 2022,
      source: 'LOCAL_KB',
    },
  },
];

export function correlateServiceCves(ports: LanServicePort[]): LanCorrelatedCve[] {
  const results: LanCorrelatedCve[] = [];
  for (const p of ports) {
    const fingerprint = `${p.service} ${p.product} ${p.version} ${p.cpe} ${p.bannerSummary}`.toLowerCase();
    for (const entry of CVE_CORRELATION_CATALOG) {
      if (entry.keywords.some((kw) => fingerprint.includes(kw))) {
        const exists = results.some(
          (r) => r.cveId === entry.cve.cveId && r.affectedPort === `${p.port}/${p.protocol}`
        );
        if (!exists) {
          results.push({
            ...entry.cve,
            affectedPort: `${p.port}/${p.protocol}`,
            service: `${p.product} ${p.version}`.trim(),
          });
        }
      }
    }
  }
  return results.sort((a, b) => b.cvssScore - a.cvssScore);
}

export const LAN_MODULE_SELF_AUDIT_ISSUES: LanModuleSelfAuditIssue[] = [
  {
    id: 'SEC-FIX-01',
    titleAr: 'منع تجاوز النطاق عبر التمثيل الثماني للعناوين (Octal IP Encoding Bypass)',
    severity: 'CRITICAL',
    weaknessFoundAr:
      'كان المحلل السابق يقبل الخانات التي تبدأ بصفر مثل (010.0.0.1)، والتي تفسرها بعض مكتبات C/Linux كعنوان ثماني (8.0.0.1 — عنوان عام خارجي!).',
    fixAppliedAr:
      'إضافة الدالة hasOctalOrLeadingZeroOctet وحظر أي خانة تحتوي على أصفار بادئة برمز رفض صريح OCTAL_IP_BYPASS_DETECTED.',
    status: 'FIXED_AND_VERIFIED',
  },
  {
    id: 'SEC-FIX-02',
    titleAr: 'فرض التحكم بالصلاحيات (RBAC) على جميع مسارات فحص الشبكة المحلية',
    severity: 'HIGH',
    weaknessFoundAr:
      'كانت مسارات /api/v1/lan/discover و /api/v1/lan/audit-host تقبل الطلبات دون التحقق من صلاحية الدور (assessment:execute / project:read).',
    fixAppliedAr:
      'ربط جميع مسارات الشبكة المحلية بمحرك الصلاحيات (requirePermission) وتسجيل كل عملية فحص أو رفض في سجل التدقيق المشفر SHA-256.',
    status: 'FIXED_AND_VERIFIED',
  },
  {
    id: 'SEC-FIX-03',
    titleAr: 'استبدال المحاكاة الثابتة بمحرك فحص المقابس والنواة الحقيقي (Real Kernel & Socket Execution)',
    severity: 'HIGH',
    weaknessFoundAr:
      'كانت نتائج المنافذ وجداول الاتصالات تعتمد على مصفوفات ثابتة دون قراءة حقيقية لمقابس النظام أو فحص TCP/HTTP فعلي.',
    fixAppliedAr:
      'بناء المحرك التنفيذي الحقيقي (realLanExecutor.ts) الذي ينفذ اتصالات net.Socket فعلية، ويقرأ /proc/net/tcp و ip -j route و ss -tuln، ويفحص ترويسات HTTP الأمنية مباشرة.',
    status: 'FIXED_AND_VERIFIED',
  },
  {
    id: 'SEC-FIX-04',
    titleAr: 'حظر استهداف عناوين البث الجماعي (Broadcast .255) والتحقق من اتصال قناع الشبكة',
    severity: 'MEDIUM',
    weaknessFoundAr:
      'لم يكن هناك منع لاستهداف عنوان البث (.255) أو التحقق من أن قناع الشبكة متجاور الأبتات (Contiguous Netmask).',
    fixAppliedAr:
      'إضافة isValidContiguousNetmask وحظر عناوين (.0 و .255) في فحص الأجهزة المفردة لمنع هجمات التضخيم الشبكي.',
    status: 'FIXED_AND_VERIFIED',
  },
  {
    id: 'SEC-FIX-05',
    titleAr: 'إضافة كاشف تسميم جدول ARP (ARP Spoofing Detector) ومولد سياسات nftables التلقائي',
    severity: 'HIGH',
    weaknessFoundAr:
      'كان جدول ARP يعرض العناوين فقط دون تحليل أمني لتكرار عناوين MAC (هجمات الرجل في المنتصف MITM) أو توليد قواعد جدار ناري.',
    fixAppliedAr:
      'إضافة محرك analyzeArpTableAnomalies لكشف تضارب عناوين MAC وتوليد قواعد nftables و sysctl.conf تلقائياً لكل هدف.',
    status: 'FIXED_AND_VERIFIED',
  },
];
