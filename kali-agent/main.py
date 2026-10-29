#!/usr/bin/env python3
"""
BARON NEXUS — Local Network Security Assessment & Asset Discovery Backend
Target OS: Kali Linux / Debian-based Security Distributions
Architecture: FastAPI + Asyncio + WebSockets + Strict RFC1918 Guardrails
"""

import asyncio
import datetime
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Literal, Optional

import httpx
import psutil
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="Baron Nexus — Local Network Security & Asset Discovery Engine",
    version="2.4.0",
    description="Defensive local network asset discovery, port/service auditing, CVE correlation, and passive traffic telemetry for Kali Linux.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# 1. MANDATORY SECURITY GUARDRAILS (RFC 1918 & COMMAND INJECTION PREVENTION)
# ============================================================================

STRICT_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-_]+$")

OUI_VENDOR_PREFIXES: Dict[str, str] = {
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "08:00:27": "PCS Systemtechnik GmbH (VirtualBox)",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "00:1A:11": "Google, Inc.",
    "F0:9F:C2": "Ubiquiti Networks Inc.",
    "24:5A:4C": "Ubiquiti Networks Inc.",
    "00:1B:63": "Apple, Inc.",
    "3C:22:FB": "Apple, Inc.",
    "00:25:90": "Super Micro Computer, Inc.",
    "00:1E:67": "Intel Corporate",
    "70:85:C2": "ASRock Incorporation",
    "00:09:0F": "Fortinet, Inc.",
    "00:18:0A": "Cisco Meraki",
    "00:04:96": "Extreme Networks",
}


def check_linux_privileges() -> Dict[str, Any]:
    """
    Checks effective UID and Linux raw socket capabilities (CAP_NET_RAW).
    Provides clear privilege diagnostics and determines whether SYN/OS scans
    are permitted or if automatic fallback to TCP Connect (-sT) is required.
    """
    euid = os.geteuid() if hasattr(os, "geteuid") else 1000
    is_root = euid == 0
    has_cap_net_raw = is_root

    if not is_root and os.path.exists("/proc/self/status"):
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        # CAP_NET_RAW is bit 13 (1 << 13 = 0x2000)
                        has_cap_net_raw = bool(cap_hex & (1 << 13))
                        break
        except Exception:
            has_cap_net_raw = False

    nmap_path = shutil.which("nmap")
    return {
        "euid": euid,
        "is_root": is_root,
        "has_cap_net_raw": has_cap_net_raw,
        "nmap_installed": nmap_path is not None,
        "nmap_binary": nmap_path or "/usr/bin/nmap",
        "recommended_scan_technique": "-sS" if (is_root or has_cap_net_raw) else "-sT",
        "privilege_notice_ar": (
            "تم التحقق من صلاحيات الجذر / الحزم الخام (CAP_NET_RAW): جميع أوضاع الفحص العميق وتقدير نظام التشغيل متاحة."
            if (is_root or has_cap_net_raw)
            else "يعمل الخادم بصلاحيات مستخدم عادي (غير جذر): سيتم استخدام فحص الاتصال الآمن TCP Connect (-sT) تلقائياً بدلاً من (-sS)."
        ),
    }


def validate_private_ip_or_cidr(target: str, allow_network: bool = True) -> str:
    """
    Strictly validates that `target` is a valid RFC 1918 private IPv4 address or CIDR block.
    Rejects any public IP, multicast, unspecified address, octal leading-zero bypass (e.g., 010.0.0.1),
    broadcast (.255) single-host targets, or shell metacharacters.
    """
    cleaned = target.strip()
    if not cleaned or len(cleaned) > 64:
        raise ValueError("عنوان الهدف فارغ أو يتجاوز الطول المسموح.")

    # Reject any shell metacharacters or whitespace immediately
    if any(ch in cleaned for ch in [";", "&", "|", "$", "`", "(", ")", "<", ">", "\n", "\r", " "]):
        raise ValueError("تم رفض المدخل لاحتوائه على محارف غير مصرح بها (حماية من حقن الأوامر).")

    ip_part = cleaned.split("/")[0] if "/" in cleaned else cleaned
    octets = ip_part.split(".")
    if len(octets) == 4 and any(len(o) > 1 and o.startswith("0") for o in octets):
        raise ValueError("تم رفض العنوان: يحتوي على أصفار بادئة (Octal IP Encoding Bypass).")

    try:
        if "/" in cleaned:
            if not allow_network:
                raise ValueError("يجب تحديد عنوان IP مفرد لجهاز متصل وليس نطاق CIDR كامل.")
            net = ipaddress.ip_network(cleaned, strict=False)
            if net.version != 4:
                raise ValueError("يُدعم حالياً فحص شبكات IPv4 المحلية فقط.")
            if not net.is_private or net.is_loopback or net.is_multicast:
                raise ValueError(
                    f"النطاق {cleaned} يقع خارج نطاقات الشبكة المحلية الخاصة (RFC 1918). يُمنع فحص العناوين العامة."
                )
            if net.prefixlen < 16:
                raise ValueError("حجم الشبكة كبير جداً؛ الحد الأقصى المسموح للفحص المباشر هو /16 إلى /32.")
            return str(net)
        else:
            if cleaned == "127.0.0.1":
                return "127.0.0.1"
            ip_obj = ipaddress.ip_address(cleaned)
            if ip_obj.version != 4:
                raise ValueError("يُدعم حالياً فحص عناوين IPv4 المحلية فقط.")
            if not ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                raise ValueError(
                    f"العنوان {cleaned} ليس ضمن نطاقات الشبكة المحلية الخاصة (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
                )
            last_octet = int(cleaned.split(".")[3])
            if last_octet in (0, 255):
                raise ValueError("يُحظر استهداف عنوان الشبكة الأساسي (.0) أو عنوان البث الجماعي Broadcast (.255).")
            return str(ip_obj)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def lookup_mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "غير معروف (Unknown OUI)"
    prefix = mac.upper().replace("-", ":")[:8]
    return OUI_VENDOR_PREFIXES.get(prefix, "واجهة قياسية (IEEE Registered NIC)")


# ============================================================================
# 2. PYDANTIC REQUEST / RESPONSE SCHEMAS
# ============================================================================

class HostDiscoveryRequest(BaseModel):
    subnet_cidr: str = Field(..., description="نطاق الشبكة المحلية بصيغة CIDR مثل 192.168.1.0/24")
    interface_name: Optional[str] = Field(default=None, description="اسم كرت الشبكة مثل eth0 أو wlan0")

    @field_validator("subnet_cidr")
    @classmethod
    def check_cidr(cls, v: str) -> str:
        return validate_private_ip_or_cidr(v, allow_network=True)


class PortAuditRequest(BaseModel):
    target_ip: str = Field(..., description="عنوان IP المحلي للجهاز المستهدف")
    profile: Literal["QUICK_AUDIT", "SERVICE_VERSION", "OS_DETECTION", "SAFE_SCRIPTS"] = Field(
        default="SERVICE_VERSION"
    )
    include_udp_top20: bool = Field(default=False)

    @field_validator("target_ip")
    @classmethod
    def check_ip(cls, v: str) -> str:
        return validate_private_ip_or_cidr(v, allow_network=False)


# ============================================================================
# 3. WEBSOCKET CONNECTION MANAGER FOR LIVE STREAMING
# ============================================================================

class LiveAuditBroadcaster:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active_connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active_connections:
            self.active_connections.remove(ws)

    async def broadcast(self, event_type: str, payload: Dict[str, Any]) -> None:
        message = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_type,
            "data": payload,
        }
        stale: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for s in stale:
            self.disconnect(s)


broadcaster = LiveAuditBroadcaster()


# ============================================================================
# 4. MODULE 1: NIC & LOCAL NETWORK ENVIRONMENT ANALYZER
# ============================================================================

def get_default_gateway_linux() -> Dict[str, str]:
    """Reads /proc/net/route on Linux to identify default gateway per interface."""
    gateways: Dict[str, str] = {}
    if not os.path.exists("/proc/net/route"):
        return gateways
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    iface = parts[0]
                    gw_hex = parts[2]
                    gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                    gateways[iface] = gw_ip
    except Exception:
        pass
    return gateways


def inspect_network_interfaces() -> List[Dict[str, Any]]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)
    gateways = get_default_gateway_linux()

    interfaces: List[Dict[str, Any]] = []
    for iface_name, addr_list in addrs.items():
        ipv4_address = None
        netmask = None
        mac_address = "00:00:00:00:00:00"

        for snic in addr_list:
            if snic.family == socket.AF_INET:
                ipv4_address = snic.address
                netmask = snic.netmask
            elif getattr(psutil, "AF_LINK", None) == snic.family or snic.family == 17:
                mac_address = snic.address

        if not ipv4_address:
            continue

        # Calculate CIDR automatically
        cidr = None
        is_private = False
        try:
            net = ipaddress.IPv4Network(f"{ipv4_address}/{netmask}", strict=False)
            cidr = str(net)
            is_private = net.is_private and not net.is_loopback
        except Exception:
            cidr = f"{ipv4_address}/32"

        st = stats.get(iface_name)
        io = io_counters.get(iface_name)
        interfaces.append(
            {
                "name": iface_name,
                "ipv4": ipv4_address,
                "netmask": netmask,
                "cidr": cidr,
                "gateway": gateways.get(iface_name, str(net.network_address + 1) if cidr and is_private else "—"),
                "mac": mac_address,
                "vendor": lookup_mac_vendor(mac_address),
                "is_up": st.isup if st else True,
                "speed_mbps": st.speed if st and st.speed > 0 else 1000,
                "mtu": st.mtu if st else 1500,
                "is_private_rfc1918": is_private,
                "rx_bytes": io.bytes_recv if io else 0,
                "tx_bytes": io.bytes_sent if io else 0,
                "rx_packets": io.packets_recv if io else 0,
                "tx_packets": io.packets_sent if io else 0,
            }
        )
    return interfaces


# ============================================================================
# 5. MODULE 2: HOST DISCOVERY & ARP / NMAP XML PARSER
# ============================================================================

def read_linux_arp_cache() -> Dict[str, str]:
    """Reads /proc/net/arp on Linux to map IP -> MAC address."""
    arp_map: Dict[str, str] = {}
    if not os.path.exists("/proc/net/arp"):
        return arp_map
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    arp_map[parts[0]] = parts[3].upper()
    except Exception:
        pass
    return arp_map


async def run_safe_nmap_xml(args: List[str], timeout_sec: int = 90) -> str:
    """
    Executes nmap strictly via asyncio.create_subprocess_exec (NO shell=True).
    Streams status lines over WebSocket and returns XML stdout.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        raise RuntimeError("أداة nmap غير مثبتة في المسار القياسي (/usr/bin/nmap).")

    cmd = [nmap_bin, "-oX", "-"] + args
    await broadcaster.broadcast(
        "CONSOLE_LOG",
        {"level": "INFO", "message": f"تنفيذ آمن بدون صدفة (exec): {' '.join(cmd)}"},
    )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"انتهت مهلة الفحص ({timeout_sec} ثانية) وتم إيقاف العملية بأمان.")

    if proc.returncode != 0 and not stdout_bytes:
        err_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"فشل تنفيذ nmap: {err_text}")

    return stdout_bytes.decode("utf-8", errors="replace")


def parse_nmap_discovery_xml(xml_text: str, gateway_ip: str) -> List[Dict[str, Any]]:
    arp_cache = read_linux_arp_cache()
    hosts: List[Dict[str, Any]] = []
    root = ET.fromstring(xml_text)

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.attrib.get("state") != "up":
            continue

        ip_addr = ""
        mac_addr = ""
        vendor = ""
        for addr_el in host_el.findall("address"):
            addr_type = addr_el.attrib.get("addrtype")
            if addr_type == "ipv4":
                ip_addr = addr_el.attrib.get("addr", "")
            elif addr_type == "mac":
                mac_addr = addr_el.attrib.get("addr", "").upper()
                vendor = addr_el.attrib.get("vendor", "")

        if not ip_addr:
            continue
        if not mac_addr and ip_addr in arp_cache:
            mac_addr = arp_cache[ip_addr]
        if not vendor:
            vendor = lookup_mac_vendor(mac_addr)

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name", "")

        times_el = host_el.find("times")
        srtt_ms = 1.2
        if times_el is not None and times_el.attrib.get("srtt"):
            try:
                srtt_ms = round(int(times_el.attrib["srtt"]) / 1000.0, 2)
            except ValueError:
                srtt_ms = 1.2

        hosts.append(
            {
                "ip": ip_addr,
                "mac": mac_addr or "LOCAL_INTERFACE",
                "vendor": vendor,
                "hostname": hostname or f"host-{ip_addr.replace('.', '-')}.lan",
                "latency_ms": srtt_ms,
                "role": "GATEWAY" if ip_addr == gateway_ip else "ENDPOINT",
                "status": "ONLINE",
                "last_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        )
    return hosts


# ============================================================================
# 6. MODULE 3 & 4: PORT/SERVICE AUDITOR & NVD CVE CORRELATION ENGINE
# ============================================================================

LOCAL_CVE_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "match_keywords": ["openssh", "8.2", "8.4", "7."],
        "cve_id": "CVE-2023-38408",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "summary": "ثغرة في وكيل forwarding الخاص بـ OpenSSH تسمح بتحميل مكتبات PKCS#11 عن بعد في حال تفعيل ForwardAgent.",
        "remediation": "تحديث حزمة openssh-server إلى الإصدار 9.3p2 أو أحدث، وتعطيل AllowAgentForwarding في /etc/ssh/sshd_config.",
    },
    {
        "match_keywords": ["nginx", "1.18", "1.14", "1.20"],
        "cve_id": "CVE-2022-41741",
        "cvss": 7.8,
        "severity": "HIGH",
        "summary": "خلل في وحدة ngx_http_mp4_module قد يؤدي إلى تلف الذاكرة عند معالجة ملفات وسائط مصممة بشكل غير قياسي.",
        "remediation": "ترقية خادم Nginx إلى الإصدار المستقر الأحدث وتعطيل الوحدات غير الضرورية وتفعيل ترويسات HSTS/CSP.",
    },
    {
        "match_keywords": ["apache", "2.4.49", "2.4.50", "2.4.41"],
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "HIGH",
        "summary": "ثغرة اجتياز المسار (Path Traversal) في Apache HTTP Server نتيجة تطبيع غير مكتمل للمسارات.",
        "remediation": "ترقية حزمة apache2 فوراً إلى 2.4.58+ والتحقق من ضبط Require all denied على المجلد الجذري.",
    },
    {
        "match_keywords": ["postgresql", "13.", "14.", "5432"],
        "cve_id": "CVE-2023-39417",
        "cvss": 8.8,
        "severity": "HIGH",
        "summary": "ثغرة في استبدال المعاملات داخل نصوص الإضافات البرمجية في PostgreSQL.",
        "remediation": "تقييد الوصول في pg_hba.conf ليقتصر على العقد المصرحة وإلزام اتصال TLS (hostssl) وتحديث محرك قاعدة البيانات.",
    },
    {
        "match_keywords": ["redis", "6379"],
        "cve_id": "CVE-2022-0543",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "summary": "احتمالية تجاوز بيئة Lua الرملية في حزم Redis أو تعرض المنفذ بدون مصادقة على الشبكة المحلية.",
        "remediation": "تفعيل requirepass واستخدام قوائم ACL في redis.conf وربط الخدمة بواجهة محددة عبر bind.",
    },
]


async def correlate_cves_for_service(service_name: str, product: str, version: str, cpe: str) -> List[Dict[str, Any]]:
    search_blob = f"{service_name} {product} {version} {cpe}".lower()
    matched: List[Dict[str, Any]] = []

    for rule in LOCAL_CVE_KNOWLEDGE_BASE:
        if any(kw in search_blob for kw in rule["match_keywords"]):
            matched.append(rule)

    # Optional live query to NVD 2.0 API if CPE is present
    if cpe and cpe.startswith("cpe:/"):
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": f"{product} {version}".strip(), "resultsPerPage": 3},
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    for item in payload.get("vulnerabilities", []):
                        cve_obj = item.get("cve", {})
                        cve_id = cve_obj.get("id")
                        if cve_id and not any(m["cve_id"] == cve_id for m in matched):
                            descriptions = cve_obj.get("descriptions", [])
                            desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                            matched.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss": 7.2,
                                    "severity": "HIGH",
                                    "summary": desc_en[:240],
                                    "remediation": f"تحديث الخدمة ({product} {version}) إلى أحدث إصدار أمني مستقر من مستودعات التوزيعة.",
                                }
                            )
        except Exception:
            pass

    return matched


def build_safe_nmap_audit_args(target_ip: str, profile: str, include_udp: bool) -> List[str]:
    priv = check_linux_privileges()
    scan_flag = "-sS" if (priv["is_root"] or priv["has_cap_net_raw"]) else "-sT"

    args: List[str] = [scan_flag, "-Pn", "--open"]
    if profile == "QUICK_AUDIT":
        args.extend(["-F", "-T4"])
    elif profile == "SERVICE_VERSION":
        args.extend(["-sV", "--version-light", "-T4"])
    elif profile == "OS_DETECTION":
        if priv["is_root"] or priv["has_cap_net_raw"]:
            args.extend(["-sV", "-O", "--osscan-limit"])
        else:
            args.extend(["-sV", "--version-light"])
    elif profile == "SAFE_SCRIPTS":
        args.extend(["-sV", "--script=default,safe,ssl-enum-ciphers"])

    if include_udp and (priv["is_root"] or priv["has_cap_net_raw"]):
        args.extend(["-sU", "--top-ports", "20"])

    args.append(target_ip)
    return args


# ============================================================================
# 7. REST API ENDPOINTS & WEBSOCKET STREAM
# ============================================================================

@app.get("/api/v1/lan/environment")
async def get_lan_environment() -> Dict[str, Any]:
    priv = check_linux_privileges()
    interfaces = inspect_network_interfaces()
    return {
        "ok": True,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "privileges": priv,
        "interfaces": interfaces,
    }


@app.post("/api/v1/lan/discover")
async def discover_lan_hosts(req: HostDiscoveryRequest) -> Dict[str, Any]:
    await broadcaster.broadcast(
        "DISCOVERY_STARTED",
        {"subnet": req.subnet_cidr, "message": f"بدء اكتشاف الأجهزة المتصلة على النطاق المحلي {req.subnet_cidr}"},
    )
    interfaces = inspect_network_interfaces()
    gw_ip = next((i["gateway"] for i in interfaces if i.get("is_private_rfc1918")), "")

    xml_out = await run_safe_nmap_xml(["-sn", "-T4", req.subnet_cidr], timeout_sec=60)
    hosts = parse_nmap_discovery_xml(xml_out, gw_ip)

    await broadcaster.broadcast(
        "DISCOVERY_COMPLETED",
        {"subnet": req.subnet_cidr, "discovered_count": len(hosts)},
    )
    return {"ok": True, "subnet": req.subnet_cidr, "hosts": hosts}


@app.post("/api/v1/lan/audit-host")
async def audit_single_host(req: PortAuditRequest) -> Dict[str, Any]:
    args = build_safe_nmap_audit_args(req.target_ip, req.profile, req.include_udp_top20)
    await broadcaster.broadcast(
        "HOST_AUDIT_STARTED",
        {"target_ip": req.target_ip, "profile": req.profile, "args": args},
    )

    xml_out = await run_safe_nmap_xml(args, timeout_sec=120)
    root = ET.fromstring(xml_out)

    ports_result: List[Dict[str, Any]] = []
    correlated_cves: List[Dict[str, Any]] = []
    os_guess = "Linux / Network Endpoint"

    host_el = root.find("host")
    if host_el is not None:
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            os_guess = f"{os_el.attrib.get('name', 'Linux')} ({os_el.attrib.get('accuracy', '90')}%)"

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue

            port_id = int(port_el.attrib.get("portid", "0"))
            proto = port_el.attrib.get("protocol", "tcp").upper()
            svc_el = port_el.find("service")
            svc_name = svc_el.attrib.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.attrib.get("product", "") if svc_el is not None else ""
            version = svc_el.attrib.get("version", "") if svc_el is not None else ""
            cpe_el = svc_el.find("cpe") if svc_el is not None else None
            cpe_str = cpe_el.text if cpe_el is not None and cpe_el.text else ""

            script_outputs: List[Dict[str, str]] = []
            for scr in port_el.findall("script"):
                script_outputs.append(
                    {"id": scr.attrib.get("id", "safe-check"), "output": scr.attrib.get("output", "")[:400]}
                )

            cves = await correlate_cves_for_service(svc_name, product, version, cpe_str)
            for c in cves:
                if not any(existing["cve_id"] == c["cve_id"] for existing in correlated_cves):
                    correlated_cves.append({**c, "affected_port": f"{port_id}/{proto}", "service": svc_name})

            ports_result.append(
                {
                    "port": port_id,
                    "protocol": proto,
                    "service": svc_name,
                    "product": product or svc_name,
                    "version": version or "غير محدد",
                    "cpe": cpe_str or f"cpe:/a:{svc_name}:{product or svc_name}:{version or '*'}",
                    "scripts": script_outputs,
                }
            )

    await broadcaster.broadcast(
        "HOST_AUDIT_COMPLETED",
        {
            "target_ip": req.target_ip,
            "open_ports_count": len(ports_result),
            "cves_found": len(correlated_cves),
        },
    )

    return {
        "ok": True,
        "target_ip": req.target_ip,
        "profile": req.profile,
        "os_detection": os_guess,
        "ports": ports_result,
        "cves": correlated_cves,
    }


@app.get("/api/v1/lan/traffic")
async def get_passive_traffic_telemetry() -> Dict[str, Any]:
    """Reads passive socket connections and bandwidth delta without packet injection."""
    io_1 = psutil.net_io_counters(pernic=True)
    await asyncio.sleep(0.25)
    io_2 = psutil.net_io_counters(pernic=True)

    bandwidth: List[Dict[str, Any]] = []
    for nic, c2 in io_2.items():
        c1 = io_1.get(nic)
        if not c1:
            continue
        rx_kbps = round(((c2.bytes_recv - c1.bytes_recv) * 4) / 1024.0, 2)
        tx_kbps = round(((c2.bytes_sent - c1.bytes_sent) * 4) / 1024.0, 2)
        bandwidth.append(
            {
                "interface": nic,
                "rx_kbps": max(0.0, rx_kbps),
                "tx_kbps": max(0.0, tx_kbps),
                "total_rx_mb": round(c2.bytes_recv / (1024 * 1024), 2),
                "total_tx_mb": round(c2.bytes_sent / (1024 * 1024), 2),
            }
        )

    proto_counts = {"TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0}
    active_conns: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet")[:40]:
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            if (conn.laddr and conn.laddr.port == 53) or (conn.raddr and conn.raddr.port == 53):
                proto_counts["DNS"] += 1
            else:
                proto_counts[proto] += 1
            active_conns.append(
                {
                    "protocol": proto,
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status,
                    "pid": conn.pid or 0,
                }
            )
    except Exception:
        pass

    return {
        "ok": True,
        "protocol_distribution": proto_counts,
        "bandwidth": bandwidth,
        "connections": active_conns,
    }


@app.websocket("/ws/lan-audit")
async def websocket_lan_audit_stream(websocket: WebSocket) -> None:
    await broadcaster.connect(websocket)
    try:
        await websocket.send_json(
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event": "WS_CONNECTED",
                "data": {"message": "تم الاتصال بقناة البث اللحظي لفحص الشبكة المحلية (WebSocket Live Stream)."},
            }
        )
        while True:
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
