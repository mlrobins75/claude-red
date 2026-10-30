#!/usr/bin/env python3
"""
CLAUDE-RED // Tactical Operator GUI & System-Prompt Builder
===========================================================
Local Web Dashboard for https://github.com/SnailSploit/claude-red

Features:
  - Hybrid Git-Vault + Disk loader: Loads all 79 offensive skills in ~70ms
    directly from the git object store if Windows Defender locks payload files.
  - Dual-Format Parser: Parses both YAML frontmatter (`---`) and legacy
    `## Metadata` / `## Description` / `## Trigger Phrases` skills.
  - Operator System-Prompt & Context Builder:
      * Combine multiple skills or cherry-pick specific `##` sections
      * Per-skill compression modes (Full, Selected Sections, Commands Only, Summary)
      * Real-time Token Budget Meter (Claude 200k context gauge)
      * Recon / Nmap Auto-Recommender (paste scan -> auto-selects matching skills)
      * Dynamic Target Variable Injection ($TARGET, $LHOST, $LPORT, $DOMAIN, $USER)
      * Built-in Role Doctrines (including CARNAGE OSCP Strike & SOP Generator)
  - Global Command & Payload Search across 11,800+ extracted code blocks
  - One-Click Installer & ZIP Exporter (~/.claude/skills, Antigravity skills, ZIP)

Usage:
  python claude_red_gui.py [--port 8765] [--no-browser]
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths & Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR / "claude-red"
if not REPO_DIR.exists() and (BASE_DIR / "Skills").exists():
    REPO_DIR = BASE_DIR

SOP_TEMPLATE_PATH = BASE_DIR / "pentest contex for llm.txt"

CATEGORY_META: dict[str, dict[str, str]] = {
    "active-directory": {"label": "Active Directory", "icon": "🏰", "focus": "Kerberoast, ADCS ESC1-15, ACLs, NetExec, Domain Dominance"},
    "web": {"label": "Web Application", "icon": "🌐", "focus": "OWASP Top 10, SQLi, SSRF, SSTI, Deserialization, Request Smuggling"},
    "api": {"label": "API Security", "icon": "🔌", "focus": "REST, gRPC, WebSockets, BOLA/BFLA, Business Logic Abuse"},
    "auth": {"label": "Auth & Identity", "icon": "🔑", "focus": "JWT Exploitation, OAuth 2.0 / OIDC Abuse, Token Tampering"},
    "privesc": {"label": "Privilege Escalation", "icon": "⚡", "focus": "Linux SUID/Capabilities/Kernel & Windows Potato/Service/UAC"},
    "post-exploitation": {"label": "Post-Exploitation", "icon": "🎯", "focus": "Lateral Movement, Persistence, Data Exfiltration"},
    "infrastructure": {"label": "Infrastructure & Red Team", "icon": "🛡️", "focus": "Initial Access, EDR Evasion, Shellcode, Windows Internals"},
    "exploit-dev": {"label": "Exploit Development", "icon": "💣", "focus": "Stack/Heap Corruption, ROP, Crash Analysis, ASLR/CFG/CET"},
    "cloud": {"label": "Cloud Security", "icon": "☁️", "focus": "AWS, Azure, GCP Privilege Escalation, IMDS, Cross-Account"},
    "container": {"label": "Container & Kubernetes", "icon": "📦", "focus": "Docker Breakout, K8s RBAC/Kubelet/Pod Escape, runc CVEs"},
    "cicd": {"label": "CI/CD & Pipelines", "icon": "⚙️", "focus": "GitHub Actions, Jenkins, GitLab CI, Vault/Secret Extraction"},
    "network": {"label": "Network Attacks", "icon": "📡", "focus": "Layer 2/3 MITM, Responder, NTLM Relay, Protocol Poisoning"},
    "wireless": {"label": "Wireless & RF", "icon": "📶", "focus": "802.11 WPA2/3, WPS, Evil Twin, BLE, Zigbee, LoRaWAN"},
    "fuzzing": {"label": "Fuzzing & Vuln Research", "icon": "🔬", "focus": "AFL++, libFuzzer, Coverage-Guided Fuzzing, Bug Taxonomy"},
    "forensics": {"label": "Forensics & C2", "icon": "🕵️", "focus": "C2 Frameworks (Sliver/Cobalt Strike/Havoc) & Anti-Forensics"},
    "crypto": {"label": "Cryptography & TLS", "icon": "🔐", "focus": "Padding Oracle, ECB, Hash Extension, TLS/SSL Attacks"},
    "mobile": {"label": "Mobile Security", "icon": "📱", "focus": "Android & iOS Frida Hooking, Pinning Bypass, Storage"},
    "iot": {"label": "IoT & Embedded", "icon": "📟", "focus": "UART/JTAG, Firmware Extraction, RTOS, MQTT/CoAP/ICS"},
    "recon": {"label": "Reconnaissance & OSINT", "icon": "🔭", "focus": "OSINT Tooling & Structured Intelligence Methodology"},
    "social-engineering": {"label": "Social Engineering", "icon": "🎭", "focus": "Phishing Infrastructure, Pretexting, Payload Delivery"},
    "supply-chain": {"label": "Supply Chain", "icon": "🔗", "focus": "Dependency Confusion, Package Typosquatting, Build Compromise"},
    "ai": {"label": "AI & LLM Security", "icon": "🧠", "focus": "Prompt Injection, Jailbreaking, RAG Poisoning, Model Exfil"},
    "utility": {"label": "Utility & Reporting", "icon": "📋", "focus": "Fast Triage Checklists & Executive/Technical Reporting"},
}

PRESET_LOADOUTS: list[dict[str, Any]] = [
    {
        "id": "oscp-web-linux",
        "name": "OSCP // Web Foothold → Linux Root",
        "description": "Fast web triage, SQLi, file upload/RCE chains, and Linux privilege escalation checklist.",
        "doctrine": "oscp_operator",
        "skills": [
            {"name": "offensive-fast-checking", "mode": "full"},
            {"name": "offensive-sqli", "mode": "commands_only"},
            {"name": "offensive-file-upload", "mode": "commands_only"},
            {"name": "offensive-rce", "mode": "commands_only"},
            {"name": "offensive-linux-privesc", "mode": "full"},
        ],
    },
    {
        "id": "oscp-ad-dominance",
        "name": "OSCP // Active Directory Domain Compromise",
        "description": "Full AD kill chain: NetExec enumeration, Kerberoast/AS-REP, BloodHound ACLs, lateral movement & Windows privesc.",
        "doctrine": "oscp_operator",
        "skills": [
            {"name": "offensive-active-directory", "mode": "full"},
            {"name": "offensive-netexec", "mode": "commands_only"},
            {"name": "offensive-windows-privesc", "mode": "commands_only"},
            {"name": "offensive-lateral-movement", "mode": "commands_only"},
        ],
    },
    {
        "id": "api-auth-hunter",
        "name": "Web/API // Modern API, GraphQL & JWT Hunter",
        "description": "OWASP API Top 10, BOLA/IDOR, GraphQL introspection/batching, JWT manipulation & OAuth abuse.",
        "doctrine": "bug_bounty",
        "skills": [
            {"name": "offensive-api-security", "mode": "full"},
            {"name": "offensive-api-abuse", "mode": "commands_only"},
            {"name": "offensive-jwt", "mode": "full"},
            {"name": "offensive-oauth", "mode": "full"},
            {"name": "offensive-graphql", "mode": "commands_only"},
        ],
    },
    {
        "id": "stealth-redteam-edr",
        "name": "Red Team // Initial Access, EDR Evasion & C2",
        "description": "OPSEC-safe initial access, userland unhooking, indirect syscalls, shellcode staging & C2 operations.",
        "doctrine": "redteam_stealth",
        "skills": [
            {"name": "offensive-initial-access", "mode": "commands_only"},
            {"name": "offensive-edr-evasion", "mode": "full"},
            {"name": "offensive-shellcode", "mode": "commands_only"},
            {"name": "offensive-c2-frameworks", "mode": "commands_only"},
        ],
    },
    {
        "id": "cloud-k8s-breakout",
        "name": "Cloud & Container // Pod Escape → Cloud Takeover",
        "description": "Docker/container escape, Kubernetes RBAC/kubelet exploitation, CI/CD secret extraction & AWS/Azure/GCP privesc.",
        "doctrine": "redteam_stealth",
        "skills": [
            {"name": "offensive-container-escape", "mode": "full"},
            {"name": "offensive-k8s-attacks", "mode": "full"},
            {"name": "offensive-cloud", "mode": "commands_only"},
            {"name": "offensive-cicd-secrets", "mode": "commands_only"},
        ],
    },
    {
        "id": "sop-report-writer",
        "name": "SOP & Reporting // Lab Transcript → Exam SOP",
        "description": "Converts raw lab notes, Nmap output, and shell transcripts into a structured OSCP Standard Operating Procedure.",
        "doctrine": "sop_mentor",
        "skills": [
            {"name": "offensive-reporting", "mode": "full"},
            {"name": "offensive-fast-checking", "mode": "summary"},
        ],
    },
]

# Rules for smart Nmap / Recon auto-recommendation
RECON_SIGNALS: list[dict[str, Any]] = [
    {
        "skills": ["offensive-active-directory", "offensive-netexec", "offensive-lateral-movement"],
        "patterns": [r"\b88/tcp\b", r"\b389/tcp\b", r"\b636/tcp\b", r"\b3268/tcp\b", r"kerberos", r"ldap", r"active directory", r"domain controller", r"bloodhound", r"krbtgt", r"adcs", r"ntds\.dit"],
        "reason": "Active Directory / Kerberos / LDAP indicators detected (Ports 88/389/636/3268 or AD terms)",
    },
    {
        "skills": ["offensive-netexec", "offensive-lateral-movement", "offensive-windows-privesc"],
        "patterns": [r"\b445/tcp\b", r"\b139/tcp\b", r"\b5985/tcp\b", r"\b5986/tcp\b", r"\b3389/tcp\b", r"\b135/tcp\b", r"microsoft-ds", r"smb", r"winrm", r"msrpc", r"rdp", r"impacket", r"psexec", r"wmiexec"],
        "reason": "Windows SMB / WinRM / RPC / RDP lateral movement & host surfaces detected (Ports 135/139/445/3389/5985)",
    },
    {
        "skills": ["offensive-sqli"],
        "patterns": [r"\b3306/tcp\b", r"\b1433/tcp\b", r"\b5432/tcp\b", r"\b1521/tcp\b", r"mysql", r"mariadb", r"postgresql", r"mssql", r"sql syntax", r"sqlmap", r"phpmyadmin", r"adminer", r"id="],
        "reason": "Database service (MySQL/PostgreSQL/MSSQL/Oracle) or SQL parameter indicators detected",
    },
    {
        "skills": ["offensive-fast-checking", "offensive-file-upload", "offensive-rce", "offensive-sqli", "offensive-xss"],
        "patterns": [r"\b80/tcp\b", r"\b443/tcp\b", r"\b8080/tcp\b", r"\b8443/tcp\b", r"apache", r"nginx", r"iis", r"http", r"ffuf", r"feroxbuster", r"gobuster", r"nikto", r"wordpress", r"php"],
        "reason": "Web application surface (HTTP/HTTPS) detected",
    },
    {
        "skills": ["offensive-jwt", "offensive-oauth", "offensive-api-security"],
        "patterns": [r"eyJ[A-Za-z0-9_-]{10,}", r"bearer\s+", r"jwt", r"oauth", r"openid", r"/.well-known/", r"redirect_uri", r"client_id", r"access_token"],
        "reason": "JWT token (`eyJ...`), Bearer auth, or OAuth/OIDC flow detected",
    },
    {
        "skills": ["offensive-graphql", "offensive-api-security", "offensive-api-abuse"],
        "patterns": [r"/graphql", r"__schema", r"introspection", r"/api/v[0-9]", r"swagger", r"openapi", r"grpc", r"websocket", r"wss?://"],
        "reason": "API / GraphQL / Swagger / gRPC / WebSocket endpoints detected",
    },
    {
        "skills": ["offensive-ssti", "offensive-rce"],
        "patterns": [r"jinja2?", r"twig", r"freemarker", r"velocity", r"werkzeug", r"flask", r"\{\{.*\}\}", r"ssti"],
        "reason": "Template engine (Jinja2/Twig/Flask/Freemarker) or SSTI expression detected",
    },
    {
        "skills": ["offensive-deserialization", "offensive-rce"],
        "patterns": [r"rO0AB", r"aced0005", r"ysoserial", r"__wakeup", r"__destruct", r"viewstate", r"pickle", r"marshal", r"java\.io\.serializable", r"tomcat", r"jboss", r"weblogic"],
        "reason": "Serialization signatures (Java `rO0AB`/`aced0005`, PHP magic methods, .NET ViewState, Python pickle) detected",
    },
    {
        "skills": ["offensive-ssrf", "offensive-cloud"],
        "patterns": [r"169\.254\.169\.254", r"metadata\.google", r"url=", r"webhook", r"callback=", r"fetch=", r"proxy=", r"amazonaws\.com", r"s3://", r"blob\.core\.windows\.net"],
        "reason": "SSRF parameter vectors or Cloud IMDS / storage indicators detected",
    },
    {
        "skills": ["offensive-container-escape", "offensive-k8s-attacks"],
        "patterns": [r"docker", r"\b2375/tcp\b", r"\b2376/tcp\b", r"\b10250/tcp\b", r"\b6443/tcp\b", r"\b2379/tcp\b", r"kubernetes", r"k8s", r"kubelet", r"etcd", r"containerd", r"/.dockerenv", r"serviceaccount"],
        "reason": "Docker / Kubernetes / Kubelet / etcd container environment indicators detected",
    },
    {
        "skills": ["offensive-cicd-pipeline", "offensive-cicd-secrets"],
        "patterns": [r"jenkins", r"gitlab", r"github actions", r"\.github/workflows", r"groovy", r"hashicorp vault", r"travis", r"azure devops", r"gitea"],
        "reason": "CI/CD platform (Jenkins/GitLab/GitHub Actions/Vault) detected",
    },
    {
        "skills": ["offensive-linux-privesc"],
        "patterns": [r"\b22/tcp\b", r"openssh", r"ubuntu", r"debian", r"centos", r"linux", r"linpeas", r"sudo -l", r"suid", r"/etc/passwd", r"crontab", r"cap_"],
        "reason": "Linux host / SSH / local enumeration indicators detected",
    },
    {
        "skills": ["offensive-windows-privesc"],
        "patterns": [r"winpeas", r"seimpersonateprivilege", r"potato", r"whoami /priv", r"unquoted service", r"alwaysinstallelevated", r"icacls", r"powershell"],
        "reason": "Windows local privilege escalation indicators detected",
    },
]


# ---------------------------------------------------------------------------
# Skill Parser & Git-Vault Loader
# ---------------------------------------------------------------------------
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
CODE_BLOCK_RE = re.compile(r"```([a-zA-Z0-9_+-]*)\n(.*?)```", re.DOTALL)
HEADING_RE = re.compile(r"^(#{1,3})\s+(.+)$", re.MULTILINE)


def parse_frontmatter_and_meta(text: str, rel_path: str) -> dict[str, Any]:
    """Parses both YAML frontmatter (`---`) and legacy `## Metadata` formats."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = Path(rel_path).parts
    category = parts[1] if len(parts) >= 3 else "utility"
    folder_name = parts[2] if len(parts) >= 3 else Path(rel_path).stem

    meta: dict[str, Any] = {
        "name": folder_name,
        "category": category,
        "path": rel_path.replace("\\", "/"),
        "description": "",
        "trigger_phrases": [],
        "source": "",
        "body": text,
    }

    m = FRONTMATTER_RE.match(text)
    if m:
        block = m.group(1)
        meta["body"] = text[m.end():].lstrip("\n")
        current_key: str | None = None
        buf: list[str] = []
        triggers: list[str] = []

        def flush_key(k: str | None, b: list[str]) -> None:
            if not k:
                return
            val = " ".join(x.strip() for x in b if x.strip() and x.strip() != ">")
            val = val.strip().strip('"').strip("'")
            if k == "name" and val:
                meta["name"] = val
            elif k == "description" and val:
                meta["description"] = val
            elif k == "source" and val:
                meta["source"] = val

        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if current_key == "trigger_phrases" and stripped.startswith("-"):
                t = stripped.lstrip("-").strip().strip('"').strip("'")
                if t:
                    triggers.append(t)
                continue
            if ":" in line and not line.startswith(" ") and not line.startswith("\t"):
                flush_key(current_key, buf)
                buf = []
                k, _, v = line.partition(":")
                current_key = k.strip().lower()
                v = v.strip()
                if v and v != ">":
                    buf.append(v)
            else:
                buf.append(stripped)
        flush_key(current_key, buf)
        if triggers:
            meta["trigger_phrases"] = triggers
    else:
        # Legacy ## Metadata / ## Description / ## Trigger Phrases format
        state = "INIT"
        desc_lines: list[str] = []
        body_lines: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            hm = re.match(r"^##\s+(.+)", stripped, re.I)
            if hm:
                sec = hm.group(1).strip().lower()
                if sec == "metadata":
                    state = "META"
                    continue
                elif sec == "description":
                    state = "DESC"
                    continue
                elif sec == "trigger phrases":
                    state = "TRIG"
                    continue
                else:
                    state = "BODY"
            if state == "META" and stripped.startswith("- **"):
                mm = re.match(r"-\s*\*\*([^*]+)\*\*\s*:\s*(.+)", stripped)
                if mm:
                    k = mm.group(1).strip().lower()
                    v = mm.group(2).strip()
                    if k == "folder":
                        meta["name"] = v
                    elif k == "source":
                        meta["source"] = v
            elif state == "DESC":
                if stripped and not stripped.startswith("#"):
                    desc_lines.append(stripped)
            elif state == "TRIG":
                tm = re.search(r"`([^`]+)`", stripped)
                if tm:
                    meta["trigger_phrases"].extend(
                        [t.strip() for t in tm.group(1).split(",") if t.strip()]
                    )
            elif state in ("BODY", "INIT"):
                body_lines.append(line)
        if desc_lines:
            meta["description"] = " ".join(desc_lines)
        if body_lines:
            meta["body"] = "\n".join(body_lines).strip()

    # Extract title from first H1 or fallback to skill name
    title_match = re.search(r"^#\s+(.+)$", meta["body"], re.M)
    if title_match:
        raw_title = title_match.group(1).strip()
        raw_title = re.sub(r"^SKILL:\s*", "", raw_title, flags=re.I)
        meta["title"] = raw_title
    else:
        meta["title"] = meta["name"].replace("offensive-", "").replace("-", " ").title()

    # Fallback description from first paragraph if still empty
    if not meta["description"]:
        for para in meta["body"].split("\n\n"):
            p = para.strip()
            if p and not p.startswith("#") and not p.startswith("```") and not p.startswith("- **"):
                meta["description"] = re.sub(r"\s+", " ", p)[:400]
                break

    # Extract trigger phrases from description if none explicit
    if not meta["trigger_phrases"] and "Use when" in meta["description"]:
        use_part = meta["description"].split("Use when", 1)[1].strip(" .")
        meta["trigger_phrases"] = [x.strip() for x in re.split(r",| or ", use_part) if x.strip()][:8]

    return meta


def parse_sections_and_code(body: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Splits markdown body into H2 sections and extracts all fenced code blocks."""
    lines = body.splitlines()
    sections: list[dict[str, Any]] = []
    cur_title = "Overview & Quick Workflow"
    cur_level = 2
    cur_lines: list[str] = []
    in_fence = False

    def flush_section(title: str, level: int, buf: list[str]) -> None:
        content = "\n".join(buf).strip()
        if not content:
            return
        sec_id = f"sec-{len(sections) + 1}-{re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')[:32]}"
        code_blocks = CODE_BLOCK_RE.findall(content)
        sections.append(
            {
                "id": sec_id,
                "title": title,
                "level": level,
                "content": content,
                "char_count": len(content),
                "token_est": max(1, len(content) // 4),
                "code_count": len(code_blocks),
            }
        )

    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
        if not in_fence:
            m = re.match(r"^(#{2})\s+(.+)$", line)
            if m:
                flush_section(cur_title, cur_level, cur_lines)
                cur_title = m.group(2).strip()
                cur_level = len(m.group(1))
                cur_lines = [line]
                continue
        cur_lines.append(line)

    flush_section(cur_title, cur_level, cur_lines)

    # Extract all code blocks with their enclosing heading context
    all_code: list[dict[str, Any]] = []
    for sec in sections:
        sec_title = sec["title"]
        # Track H3 subheadings inside section
        sub_heading = sec_title
        pos = 0
        sec_text = sec["content"]
        for cm in CODE_BLOCK_RE.finditer(sec_text):
            before = sec_text[pos:cm.start()]
            h3s = re.findall(r"^###\s+(.+)$", before, re.M)
            if h3s:
                sub_heading = f"{sec_title} › {h3s[-1].strip()}"
            pos = cm.end()
            lang = (cm.group(1) or "text").strip().lower()
            code_str = cm.group(2).strip()
            if code_str:
                all_code.append(
                    {
                        "id": len(all_code) + 1,
                        "lang": lang,
                        "section": sub_heading,
                        "code": code_str,
                    }
                )

    return sections, all_code


class SkillRepository:
    """In-memory index of all claude-red skills with hybrid Disk + Git-Vault loading."""

    def __init__(self, repo_dir: Path) -> None:
        self.repo_dir = repo_dir
        self.skills_by_name: dict[str, dict[str, Any]] = {}
        self.skills_by_path: dict[str, dict[str, Any]] = {}
        self.mindmap_md: str = ""
        self.readme_md: str = ""
        self.sop_template: str = ""
        self.load_time_ms: float = 0.0
        self.reload()

    def reload(self) -> None:
        t0 = time.time()
        self.skills_by_name.clear()
        self.skills_by_path.clear()

        if SOP_TEMPLATE_PATH.is_file():
            try:
                self.sop_template = SOP_TEMPLATE_PATH.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        # 1. Load git archive into memory first (avoids Windows Defender locks on payload files)
        git_files: dict[str, str] = {}
        if (self.repo_dir / ".git").exists():
            try:
                raw_tar = subprocess.check_output(
                    ["git", "-C", str(self.repo_dir), "archive", "--format=tar", "HEAD"],
                    stderr=subprocess.DEVNULL,
                )
                with tarfile.open(fileobj=io.BytesIO(raw_tar)) as tf:
                    for member in tf.getmembers():
                        if member.isfile() and (
                            member.name.endswith(".md") or member.name.endswith(".json")
                        ):
                            fobj = tf.extractfile(member)
                            if fobj:
                                git_files[member.name.replace("\\", "/")] = fobj.read().decode(
                                    "utf-8", errors="replace"
                                )
            except Exception as exc:
                print(f"[!] Git archive fallback notice: {exc}", file=sys.stderr)

        # 2. Discover any local SKILL.md files on disk (allows user edits / custom skills)
        disk_paths: set[str] = set()
        skills_root = self.repo_dir / "Skills"
        if skills_root.is_dir():
            for p in skills_root.rglob("SKILL.md"):
                rel = str(p.relative_to(self.repo_dir)).replace("\\", "/")
                disk_paths.add(rel)

        all_skill_paths = sorted(
            {k for k in git_files if k.startswith("Skills/") and k.endswith("SKILL.md")}
            | disk_paths
        )

        for rel_path in all_skill_paths:
            raw_text: str | None = None
            source_mode = "GIT-VAULT"
            disk_file = self.repo_dir / rel_path
            if disk_file.is_file():
                try:
                    raw_text = disk_file.read_text(encoding="utf-8", errors="replace")
                    source_mode = "DISK"
                except OSError:
                    # Blocked by Windows Defender -> seamlessly fall back to Git Vault!
                    raw_text = git_files.get(rel_path)
                    source_mode = "GIT-VAULT (Defender Bypassed)"
            if raw_text is None:
                raw_text = git_files.get(rel_path, "")

            if not raw_text:
                continue

            meta = parse_frontmatter_and_meta(raw_text, rel_path)
            sections, code_blocks = parse_sections_and_code(meta["body"])

            skill_record = {
                "name": meta["name"],
                "title": meta["title"],
                "category": meta["category"],
                "category_label": CATEGORY_META.get(meta["category"], {}).get(
                    "label", meta["category"].replace("-", " ").title()
                ),
                "category_icon": CATEGORY_META.get(meta["category"], {}).get("icon", "📁"),
                "path": meta["path"],
                "description": meta["description"],
                "trigger_phrases": meta["trigger_phrases"],
                "source": meta["source"],
                "source_mode": source_mode,
                "raw": raw_text,
                "body": meta["body"],
                "char_count": len(raw_text),
                "token_est": max(1, len(raw_text) // 4),
                "section_count": len(sections),
                "code_block_count": len(code_blocks),
                "sections": sections,
                "code_blocks": code_blocks,
            }
            self.skills_by_name[skill_record["name"]] = skill_record
            self.skills_by_path[skill_record["path"]] = skill_record

        self.mindmap_md = git_files.get("MINDMAP.md", "")
        if not self.mindmap_md and (self.repo_dir / "MINDMAP.md").is_file():
            try:
                self.mindmap_md = (self.repo_dir / "MINDMAP.md").read_text(encoding="utf-8")
            except OSError:
                pass

        self.readme_md = git_files.get("README.md", "")
        self.load_time_ms = round((time.time() - t0) * 1000, 1)

    def get_index_payload(self) -> dict[str, Any]:
        skills_summary = []
        categories_map: dict[str, dict[str, Any]] = {}

        for s in sorted(self.skills_by_name.values(), key=lambda x: (x["category"], x["name"])):
            cat = s["category"]
            if cat not in categories_map:
                cmeta = CATEGORY_META.get(cat, {})
                categories_map[cat] = {
                    "id": cat,
                    "label": cmeta.get("label", cat.replace("-", " ").title()),
                    "icon": cmeta.get("icon", "📁"),
                    "focus": cmeta.get("focus", ""),
                    "count": 0,
                    "skills": [],
                }
            categories_map[cat]["count"] += 1
            categories_map[cat]["skills"].append(s["name"])

            skills_summary.append(
                {
                    "name": s["name"],
                    "title": s["title"],
                    "category": s["category"],
                    "category_label": s["category_label"],
                    "category_icon": s["category_icon"],
                    "path": s["path"],
                    "description": s["description"],
                    "trigger_phrases": s["trigger_phrases"],
                    "source_mode": s["source_mode"],
                    "char_count": s["char_count"],
                    "token_est": s["token_est"],
                    "section_count": s["section_count"],
                    "code_block_count": s["code_block_count"],
                    "sections": [
                        {
                            "id": sec["id"],
                            "title": sec["title"],
                            "token_est": sec["token_est"],
                            "code_count": sec["code_count"],
                        }
                        for sec in s["sections"]
                    ],
                }
            )

        total_tokens = sum(s["token_est"] for s in skills_summary)
        total_code = sum(s["code_block_count"] for s in skills_summary)
        total_sections = sum(s["section_count"] for s in skills_summary)

        return {
            "repo_path": str(self.repo_dir),
            "load_time_ms": self.load_time_ms,
            "skill_count": len(skills_summary),
            "category_count": len(categories_map),
            "total_tokens": total_tokens,
            "total_code_blocks": total_code,
            "total_sections": total_sections,
            "categories": list(categories_map.values()),
            "skills": skills_summary,
            "presets": PRESET_LOADOUTS,
            "mindmap_md": self.mindmap_md,
        }


# ---------------------------------------------------------------------------
# Prompt Compiler & Variable Substitution Engine
# ---------------------------------------------------------------------------
DOCTRINES: dict[str, dict[str, str]] = {
    "oscp_operator": {
        "name": "CARNAGE // OSCP Strike & Tactical Operator",
        "system": (
            "You are an elite offensive security operator and OSCP tactical advisor operating under the "
            "FM200 Trinity methodology (HANNIBAL Recon | CARNAGE Strike/Post | GROOT Loot).\n"
            "Rules of Engagement:\n"
            "1. Prioritize high-probability, low-noise enumeration and exploitation paths.\n"
            "2. Provide exact, copy-pasteable terminal commands tailored to the target variables.\n"
            "3. Never rely on automated SQLmap/Metasploit modules when manual exploitation or exam restrictions apply unless asked.\n"
            "4. For every phase, state: Objective -> Exact Command -> Expected Signal -> Next Decision Point -> Fallback if Blocked."
        ),
    },
    "redteam_stealth": {
        "name": "Red Team // OPSEC & Adversary Simulation",
        "system": (
            "You are a senior Red Team operator specializing in stealthy initial access, EDR/AV evasion, "
            "Active Directory tradecraft, and post-exploitation OPSEC.\n"
            "Rules of Engagement:\n"
            "1. Highlight detection telemetry (ETW, AMSI, Sysmon Event IDs, MDI sensors) before suggesting noisy actions.\n"
            "2. Prefer living-off-the-land, in-memory execution, indirect syscalls, and ACL/delegation abuse over dropping noisy binaries.\n"
            "3. Provide exact operator commands, Bof/beacon workflows, and cleanup procedures."
        ),
    },
    "bug_bounty": {
        "name": "Bug Bounty // High-Impact Vulnerability Hunter",
        "system": (
            "You are a principal application security researcher and bug bounty hunter.\n"
            "Rules of Engagement:\n"
            "1. Focus on chained business logic flaws, auth/JWT/OAuth bypasses, SSRF pivots, and high-severity CVSS vectors.\n"
            "2. Provide reproducible HTTP requests, curl commands, and PoC payloads ready for Burp Repeater / Caido.\n"
            "3. Explain root cause and remediation clearly for high-signal triage reports."
        ),
    },
    "sop_mentor": {
        "name": "SOP Mentor // Lab Transcript to Standard Operating Procedure",
        "system": "",  # Populated dynamically from user's `pentest contex for llm.txt`
    },
}


def substitute_variables(text: str, context: dict[str, str]) -> str:
    """Replaces common placeholder tokens in skill commands with operator target values."""
    if not context.get("auto_substitute"):
        return text

    target = context.get("target", "").strip()
    lhost = context.get("lhost", "").strip()
    lport = context.get("lport", "").strip()
    domain = context.get("domain", "").strip()
    user = context.get("user", "").strip()

    out = text
    if target:
        out = re.sub(r"\b10\.10\.10\.\d+\b", target, out)
        out = re.sub(r"<target(?:_ip)?>|\$TARGET\b|\$\{TARGET\}", target, out, flags=re.I)
    if lhost:
        out = re.sub(r"<attacker(?:_ip)?>|<lhost>|\$LHOST\b|\$\{LHOST\}", lhost, out, flags=re.I)
    if lport:
        out = re.sub(r"<lport>|\$LPORT\b|\$\{LPORT\}", lport, out, flags=re.I)
    if domain:
        out = re.sub(r"\bcorp\.local\b|\bdomain\.local\b|<domain>|\$DOMAIN\b", domain, out, flags=re.I)
    if user:
        out = re.sub(r"<user(?:name)?>|\$USER\b", user, out, flags=re.I)
    return out


def compress_skill_content(
    skill: dict[str, Any],
    mode: str,
    selected_sections: list[str] | None = None,
) -> str:
    """Formats a skill according to the requested compression mode."""
    if mode == "summary":
        sec_list = "\n".join(f"  - {s['title']}" for s in skill["sections"][:15])
        first_sec = skill["sections"][0]["content"] if skill["sections"] else ""
        return (
            f"### Skill: `{skill['name']}` ({skill['category_label']})\n"
            f"**Summary:** {skill['description']}\n\n"
            f"{first_sec}\n\n"
            f"**Available Methodology Sections:**\n{sec_list}"
        )

    if mode == "sections" and selected_sections:
        chosen = [s for s in skill["sections"] if s["id"] in selected_sections]
        if not chosen:
            chosen = skill["sections"][:1]
        blocks = "\n\n---\n\n".join(s["content"] for s in chosen)
        return f"# SKILL: {skill['title']} (`{skill['name']}` — Selected Sections)\n\n{blocks}"

    if mode == "commands_only":
        parts = [
            f"# SKILL: {skill['title']} (`{skill['name']}` — Tactical Commands & Checklists)",
            f"> {skill['description']}",
        ]
        for sec in skill["sections"]:
            # Keep headings, numbered workflow lines, and fenced code blocks
            kept_lines: list[str] = []
            in_code = False
            for line in sec["content"].splitlines():
                sline = line.strip()
                if sline.startswith("```"):
                    in_code = not in_code
                    kept_lines.append(line)
                elif in_code:
                    kept_lines.append(line)
                elif sline.startswith("#") or re.match(r"^(\d+\.|- \[[ x]\])\s+", sline):
                    kept_lines.append(line)
            if any(l.strip().startswith("```") for l in kept_lines) or len(kept_lines) > 2:
                parts.append("\n".join(kept_lines))
        return "\n\n".join(parts)

    # Default: "full"
    return f"# SKILL: {skill['title']} (`{skill['name']}`)\n\n{skill['body']}"


def compile_operator_prompt(repo: SkillRepository, payload: dict[str, Any]) -> dict[str, Any]:
    """Compiles the selected skills, doctrine, and engagement context into an LLM prompt."""
    items = payload.get("skills", [])
    doctrine_key = payload.get("doctrine", "oscp_operator")
    output_format = payload.get("format", "xml_system")
    context = payload.get("context", {})

    doctrine_text = DOCTRINES.get(doctrine_key, DOCTRINES["oscp_operator"])["system"]
    if doctrine_key == "sop_mentor":
        doctrine_text = repo.sop_template or DOCTRINES["oscp_operator"]["system"]

    custom_doctrine = (context.get("custom_instructions") or "").strip()
    if custom_doctrine:
        doctrine_text = f"{doctrine_text}\n\nAdditional Operator Directives:\n{custom_doctrine}"

    compiled_skills: list[str] = []
    skill_breakdown: list[dict[str, Any]] = []

    for item in items:
        sname = item.get("name")
        mode = item.get("mode", "full")
        sec_ids = item.get("sections", [])
        skill = repo.skills_by_name.get(sname)
        if not skill:
            continue
        rendered = compress_skill_content(skill, mode, sec_ids)
        rendered = substitute_variables(rendered, context)
        toks = max(1, len(rendered) // 4)
        compiled_skills.append(rendered)
        skill_breakdown.append(
            {
                "name": sname,
                "mode": mode,
                "tokens": toks,
                "chars": len(rendered),
            }
        )

    # Engagement Context block
    ctx_lines = []
    for k, label in [
        ("target", "Target Host / IP (TARGET)"),
        ("lhost", "Operator Attack IP (LHOST)"),
        ("lport", "Listener Port (LPORT)"),
        ("domain", "Target Domain / AD Forest"),
        ("user", "Known Username / Credentials"),
        ("objective", "Current Phase / Primary Objective"),
    ]:
        val = (context.get(k) or "").strip()
        if val:
            ctx_lines.append(f"- **{label}**: `{val}`")

    recon_notes = (context.get("recon_notes") or "").strip()

    if output_format == "claude_cli":
        paths = [
            repo.skills_by_name[it["name"]]["path"]
            for it in items
            if it.get("name") in repo.skills_by_name
        ]
        paths_str = " ".join(f'"{p}"' for p in paths) or '"Skills/web/offensive-sqli/SKILL.md"'
        task_hint = (context.get("objective") or "Analyze target and provide tactical attack plan").replace('"', '\\"')
        prompt_text = (
            f"# --- Option 1: Bash / WSL / macOS Claude Code CLI ---\n"
            f"cat {paths_str} | claude --system-file - \"{task_hint}\"\n\n"
            f"# --- Option 2: PowerShell (Windows) Claude Code CLI ---\n"
            f"Get-Content {paths_str} | claude --system-file - \"{task_hint}\"\n"
        )
    elif output_format == "consolidated_skill_md":
        names = [it["name"] for it in items if it.get("name") in repo.skills_by_name]
        triggers = []
        for n in names:
            triggers.extend(repo.skills_by_name[n]["trigger_phrases"][:4])
        trig_yaml = "\n".join(f'  - "{t}"' for t in dict.fromkeys(triggers))
        default_trig = '  - "red team"'
        prompt_text = (
            f"---\n"
            f"name: offensive-custom-bundle\n"
            f"description: \"Custom claude-red operator bundle combining: {', '.join(names)}\"\n"
            f"trigger_phrases:\n{trig_yaml or default_trig}\n"
            f"---\n\n"
            f"{doctrine_text}\n\n"
            + "\n\n---\n\n".join(compiled_skills)
        )
    else:
        # Structured XML + Markdown System Prompt (Optimal for Claude 3.5/4 & ChatGPT)
        parts = ["<operator_doctrine>\n" + doctrine_text + "\n</operator_doctrine>"]
        if ctx_lines:
            parts.append(
                "<engagement_variables>\n" + "\n".join(ctx_lines) + "\n</engagement_variables>"
            )
        if compiled_skills:
            parts.append(
                "<claude_red_skills>\n"
                + "\n\n================================================================================\n\n".join(
                    compiled_skills
                )
                + "\n</claude_red_skills>"
            )
        if recon_notes:
            parts.append(
                "<target_recon_and_transcript>\n" + recon_notes + "\n</target_recon_and_transcript>"
            )
        task_str = (
            context.get("objective")
            or "Analyze the target telemetry against the loaded claude-red skills. Provide a prioritized attack plan with exact copy-pasteable commands, expected outputs, and escalation paths."
        )
        parts.append(f"<operator_task>\n{task_str}\n</operator_task>")
        prompt_text = "\n\n".join(parts)

    total_chars = len(prompt_text)
    total_tokens = max(1, total_chars // 4)

    return {
        "prompt": prompt_text,
        "char_count": total_chars,
        "token_est": total_tokens,
        "context_pct_200k": round((total_tokens / 200000) * 100, 2),
        "skill_breakdown": skill_breakdown,
    }


# ---------------------------------------------------------------------------
# Frontend SPA HTML/CSS/JS
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CLAUDE-RED // Tactical Operator Console & Prompt Builder</title>
<style>
  :root {
    --bg-0: #07080c;
    --bg-1: #0d1017;
    --bg-2: #141923;
    --bg-3: #1c2331;
    --border: #263042;
    --border-hi: #ef4444;
    --red: #ef4444;
    --red-dim: rgba(239, 68, 68, 0.14);
    --red-glow: rgba(239, 68, 68, 0.35);
    --amber: #f59e0b;
    --amber-dim: rgba(245, 158, 11, 0.14);
    --emerald: #10b981;
    --emerald-dim: rgba(16, 185, 129, 0.14);
    --cyan: #06b6d4;
    --cyan-dim: rgba(6, 182, 212, 0.14);
    --text-0: #f3f4f6;
    --text-1: #cbd5e1;
    --text-2: #94a3b8;
    --text-3: #64748b;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-0);
    color: var(--text-0);
    font-family: var(--font-sans);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  ::-webkit-scrollbar { width: 7px; height: 7px; }
  ::-webkit-scrollbar-track { background: var(--bg-0); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-3); }

  /* Top Header */
  header {
    height: 58px;
    background: linear-gradient(90deg, #0b0d14 0%, #150d12 50%, #0b0d14 100%);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 18px;
    flex-shrink: 0;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .brand-logo {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: var(--red-dim);
    border: 1px solid var(--red);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    color: var(--red);
    font-family: var(--font-mono);
    box-shadow: 0 0 14px var(--red-glow);
  }
  .brand-title {
    font-family: var(--font-mono);
    font-weight: 800;
    font-size: 16px;
    letter-spacing: 0.8px;
    color: var(--text-0);
  }
  .brand-title span { color: var(--red); }
  .brand-sub {
    font-size: 11px;
    color: var(--text-2);
    font-family: var(--font-mono);
  }

  /* Nav Tabs */
  .nav-tabs {
    display: flex;
    gap: 6px;
    background: var(--bg-1);
    padding: 4px;
    border-radius: 8px;
    border: 1px solid var(--border);
  }
  .nav-tab {
    background: transparent;
    color: var(--text-2);
    border: none;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 7px;
    transition: all 0.15s;
  }
  .nav-tab:hover { color: var(--text-0); background: var(--bg-2); }
  .nav-tab.active {
    background: var(--red);
    color: #fff;
    box-shadow: 0 0 12px var(--red-glow);
  }
  .badge-pill {
    font-family: var(--font-mono);
    font-size: 10.5px;
    padding: 1px 6px;
    border-radius: 10px;
    background: rgba(0,0,0,0.35);
    color: inherit;
  }

  .header-stats {
    display: flex;
    align-items: center;
    gap: 14px;
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--text-2);
  }
  .stat-chip {
    background: var(--bg-1);
    border: 1px solid var(--border);
    padding: 5px 10px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .stat-chip strong { color: var(--text-0); }

  /* Global Target Context Bar */
  .target-bar {
    background: var(--bg-1);
    border-bottom: 1px solid var(--border);
    padding: 7px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
    flex-wrap: wrap;
  }
  .target-bar-label {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    color: var(--red);
    text-transform: uppercase;
    letter-spacing: 0.7px;
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .ctx-field {
    display: flex;
    align-items: center;
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: 5px;
    overflow: hidden;
  }
  .ctx-field span {
    font-family: var(--font-mono);
    font-size: 10.5px;
    color: var(--text-3);
    padding: 4px 7px;
    background: var(--bg-2);
    border-right: 1px solid var(--border);
  }
  .ctx-field input {
    background: transparent;
    border: none;
    color: var(--emerald);
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 4px 8px;
    width: 115px;
    outline: none;
  }
  .ctx-field input::placeholder { color: var(--text-3); }

  /* Workspace Layout */
  .workspace {
    flex: 1;
    display: flex;
    overflow: hidden;
  }
  .view-panel {
    display: none;
    width: 100%;
    height: 100%;
    overflow: hidden;
  }
  .view-panel.active {
    display: flex;
  }

  /* Left Sidebar (Categories & Skill List) */
  .sidebar {
    width: 330px;
    background: var(--bg-1);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }
  .sidebar-search {
    padding: 12px;
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .search-input {
    width: 100%;
    background: var(--bg-0);
    border: 1px solid var(--border);
    color: var(--text-0);
    padding: 8px 11px;
    border-radius: 6px;
    font-size: 12.5px;
    outline: none;
  }
  .search-input:focus { border-color: var(--red); }
  .category-pills {
    display: flex;
    gap: 5px;
    overflow-x: auto;
    padding-bottom: 4px;
  }
  .cat-pill {
    background: var(--bg-2);
    border: 1px solid var(--border);
    color: var(--text-2);
    font-size: 11px;
    padding: 4px 8px;
    border-radius: 5px;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.12s;
  }
  .cat-pill:hover { color: var(--text-0); border-color: var(--text-3); }
  .cat-pill.active {
    background: var(--red-dim);
    border-color: var(--red);
    color: #fff;
    font-weight: 600;
  }
  .skill-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .skill-item {
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 9px 11px;
    cursor: pointer;
    transition: all 0.12s;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .skill-item:hover {
    border-color: var(--text-3);
    background: var(--bg-2);
  }
  .skill-item.selected {
    border-color: var(--red);
    background: linear-gradient(90deg, rgba(239,68,68,0.12) 0%, var(--bg-2) 100%);
  }
  .skill-item-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }
  .skill-item-name {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--text-0);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .skill-item-desc {
    font-size: 11.5px;
    color: var(--text-2);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    line-height: 1.35;
  }
  .skill-item-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 3px;
    font-family: var(--font-mono);
    font-size: 10.5px;
    color: var(--text-3);
  }

  /* Buttons */
  .btn {
    background: var(--bg-2);
    border: 1px solid var(--border);
    color: var(--text-1);
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.14s;
  }
  .btn:hover { background: var(--bg-3); color: #fff; border-color: var(--text-3); }
  .btn-red {
    background: var(--red);
    border-color: var(--red);
    color: #fff;
  }
  .btn-red:hover { background: #dc2626; border-color: #dc2626; }
  .btn-emerald {
    background: var(--emerald-dim);
    border-color: var(--emerald);
    color: var(--emerald);
  }
  .btn-emerald:hover { background: var(--emerald); color: #000; }
  .btn-amber {
    background: var(--amber-dim);
    border-color: var(--amber);
    color: var(--amber);
  }
  .btn-sm { padding: 3px 8px; font-size: 11px; border-radius: 4px; }

  /* Main Detail Area */
  .main-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--bg-0);
  }
  .skill-header {
    padding: 16px 22px;
    background: var(--bg-1);
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .skill-header-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }
  .skill-title {
    font-size: 20px;
    font-weight: 800;
    color: var(--text-0);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .skill-path {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--text-3);
    margin-top: 2px;
  }
  .skill-desc-box {
    font-size: 13px;
    color: var(--text-1);
    line-height: 1.5;
    background: var(--bg-0);
    border: 1px solid var(--border);
    padding: 10px 14px;
    border-radius: 6px;
  }
  .trigger-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
  }
  .trigger-tag {
    font-family: var(--font-mono);
    font-size: 11px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    color: var(--cyan);
    padding: 2px 8px;
    border-radius: 4px;
  }
  .sub-tabs {
    display: flex;
    gap: 16px;
    border-bottom: 1px solid var(--border);
    padding: 0 22px;
    background: var(--bg-1);
  }
  .sub-tab {
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-2);
    padding: 10px 4px;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
  }
  .sub-tab.active {
    color: var(--red);
    border-bottom-color: var(--red);
  }

  .skill-body-wrap {
    flex: 1;
    display: flex;
    overflow: hidden;
  }
  .toc-rail {
    width: 250px;
    border-right: 1px solid var(--border);
    background: var(--bg-1);
    overflow-y: auto;
    padding: 12px;
    flex-shrink: 0;
  }
  .toc-title {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
    color: var(--text-2);
    text-transform: uppercase;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .toc-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 5px 7px;
    border-radius: 5px;
    font-size: 12px;
    color: var(--text-1);
    cursor: pointer;
    margin-bottom: 3px;
  }
  .toc-item:hover { background: var(--bg-2); color: #fff; }
  .toc-item-left {
    display: flex;
    align-items: center;
    gap: 7px;
    overflow: hidden;
  }
  .toc-item-left span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .toc-tok {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-3);
    flex-shrink: 0;
  }

  .markdown-Stream {
    flex: 1;
    overflow-y: auto;
    padding: 22px 28px;
    line-height: 1.6;
  }
  .sec-card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 18px;
  }
  .sec-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 14px;
  }
  .sec-card-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--red);
    font-family: var(--font-mono);
  }
  .md-content h3 {
    color: var(--text-0);
    font-size: 14px;
    margin: 16px 0 8px 0;
    font-family: var(--font-mono);
  }
  .md-content p, .md-content li {
    font-size: 13.5px;
    color: var(--text-1);
    margin-bottom: 6px;
  }
  .md-content ul, .md-content ol { padding-left: 22px; margin-bottom: 10px; }
  .md-content code.inline {
    background: var(--bg-3);
    color: var(--amber);
    padding: 1px 5px;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .code-box {
    background: #05070a;
    border: 1px solid var(--border);
    border-radius: 6px;
    margin: 10px 0 14px 0;
    overflow: hidden;
  }
  .code-box-bar {
    background: var(--bg-2);
    padding: 5px 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-2);
    border-bottom: 1px solid var(--border);
  }
  .code-box pre {
    padding: 12px 14px;
    overflow-x: auto;
    font-family: var(--font-mono);
    font-size: 12px;
    color: #e2e8f0;
    line-height: 1.45;
  }

  /* Prompt Builder View */
  .builder-grid {
    display: grid;
    grid-template-columns: 370px 380px 1fr;
    width: 100%;
    height: 100%;
    overflow: hidden;
  }
  .builder-col {
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: var(--bg-1);
  }
  .builder-col:last-child { border-right: none; background: var(--bg-0); }
  .col-header {
    padding: 12px 16px;
    background: var(--bg-2);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--text-0);
  }
  .col-body {
    flex: 1;
    overflow-y: auto;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .preset-card {
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 10px 12px;
    cursor: pointer;
    transition: all 0.13s;
  }
  .preset-card:hover { border-color: var(--red); background: var(--bg-2); }
  .preset-card-title {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--amber);
    margin-bottom: 4px;
  }
  .preset-card-desc { font-size: 11.5px; color: var(--text-2); }

  .stack-card {
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .stack-card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .stack-card-name {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--text-0);
  }
  .mode-select, .form-select, .form-textarea, .form-input {
    width: 100%;
    background: var(--bg-0);
    border: 1px solid var(--border);
    color: var(--text-0);
    padding: 7px 10px;
    border-radius: 5px;
    font-size: 12px;
    font-family: var(--font-sans);
    outline: none;
  }
  .form-textarea {
    font-family: var(--font-mono);
    resize: vertical;
    min-height: 90px;
  }
  .form-label {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-2);
    font-weight: 600;
    margin-bottom: 4px;
    display: block;
  }

  /* Token Gauge */
  .token-meter {
    background: var(--bg-1);
    border-bottom: 1px solid var(--border);
    padding: 12px 18px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .token-bar-bg {
    width: 100%;
    height: 8px;
    background: var(--bg-3);
    border-radius: 4px;
    overflow: hidden;
  }
  .token-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--emerald) 0%, var(--amber) 70%, var(--red) 100%);
    width: 0%;
    transition: width 0.25s;
  }
  .prompt-preview {
    flex: 1;
    width: 100%;
    background: #05070a;
    color: #e2e8f0;
    border: none;
    padding: 18px;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.5;
    resize: none;
    outline: none;
  }

  /* Toast notification */
  #toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--bg-2);
    border: 1px solid var(--emerald);
    color: var(--text-0);
    padding: 10px 16px;
    border-radius: 8px;
    font-family: var(--font-mono);
    font-size: 12px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.6);
    display: none;
    z-index: 9999;
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-logo">CR</div>
    <div>
      <div class="brand-title">CLAUDE-<span>RED</span> // OPERATOR CONSOLE</div>
      <div class="brand-sub">SnailSploit Offensive Skill Library &amp; Tactical Prompt Compiler</div>
    </div>
  </div>

  <div class="nav-tabs">
    <button class="nav-tab active" onclick="switchView('explorer', this)">
      📚 Skill Arsenal <span class="badge-pill" id="nav-skill-count">79</span>
    </button>
    <button class="nav-tab" onclick="switchView('builder', this)">
      ⚡ Operator Prompt Builder <span class="badge-pill" id="nav-stack-count">0</span>
    </button>
    <button class="nav-tab" onclick="switchView('commands', this)">
      💻 Global Command Search <span class="badge-pill" id="nav-cmd-count">11.8k</span>
    </button>
    <button class="nav-tab" onclick="switchView('installer', this)">
      📦 Mindmap &amp; Installer
    </button>
  </div>

  <div class="header-stats">
    <div class="stat-chip">⚡ Vault: <strong id="stat-load-ms">0ms</strong></div>
    <div class="stat-chip">🛡️ Defender Bypass: <strong style="color:var(--emerald)">ACTIVE</strong></div>
  </div>
</header>

<!-- Global Engagement Variables Bar -->
<div class="target-bar">
  <div class="target-bar-label">🎯 Target Variables:</div>
  <div class="ctx-field"><span>$TARGET</span><input id="g-target" placeholder="10.10.11.24" oninput="onGlobalVarChange()"></div>
  <div class="ctx-field"><span>$LHOST</span><input id="g-lhost" placeholder="10.10.14.5" oninput="onGlobalVarChange()"></div>
  <div class="ctx-field"><span>$LPORT</span><input id="g-lport" placeholder="4444" style="width:70px" oninput="onGlobalVarChange()"></div>
  <div class="ctx-field"><span>$DOMAIN</span><input id="g-domain" placeholder="corp.local" oninput="onGlobalVarChange()"></div>
  <div class="ctx-field"><span>$USER</span><input id="g-user" placeholder="svc_sql" style="width:95px" oninput="onGlobalVarChange()"></div>
  <label style="font-size:11.5px;color:var(--text-2);display:flex;align-items:center;gap:5px;cursor:pointer;margin-left:4px;">
    <input type="checkbox" id="g-autosub" checked onchange="onGlobalVarChange()"> Auto-Substitute in Commands &amp; Prompts
  </label>
</div>

<div class="workspace">

  <!-- ==================== VIEW 1: SKILL ARSENAL EXPLORER ==================== -->
  <div id="view-explorer" class="view-panel active">
    <div class="sidebar">
      <div class="sidebar-search">
        <input type="text" id="skill-filter" class="search-input" placeholder="Search 79 skills, triggers, CVEs, tools..." oninput="renderSkillList()">
        <div class="category-pills" id="category-pills"></div>
      </div>
      <div class="skill-list" id="skill-list"></div>
    </div>

    <div class="main-pane" id="skill-detail-pane">
      <div style="padding:40px;color:var(--text-2);font-family:var(--font-mono);">Loading skill library...</div>
    </div>
  </div>

  <!-- ==================== VIEW 2: OPERATOR PROMPT BUILDER ==================== -->
  <div id="view-builder" class="view-panel">
    <div class="builder-grid">

      <!-- Column 1: Presets & Recon Auto-Matcher -->
      <div class="builder-col">
        <div class="col-header">
          <span>1. LOADOUT PRESETS &amp; RECON MATCHER</span>
        </div>
        <div class="col-body">
          <div>
            <span class="form-label">🔥 One-Click Tactical Loadouts</span>
            <div id="preset-list" style="display:flex;flex-direction:column;gap:7px;"></div>
          </div>

          <hr style="border:none;border-top:1px solid var(--border);margin:4px 0;">

          <div>
            <span class="form-label">🛰️ Auto-Recommend Skills from Nmap / Recon</span>
            <textarea id="recon-input" class="form-textarea" placeholder="Paste Nmap output, open ports (e.g. 80, 88, 389, 445, 5985), HTTP headers, or target notes here..."></textarea>
            <button class="btn btn-emerald" style="width:100%;margin-top:6px;justify-content:center;" onclick="runReconMatcher()">
              🔍 Auto-Detect &amp; Stack Matching Skills
            </button>
            <div id="recon-results" style="margin-top:8px;display:flex;flex-direction:column;gap:6px;"></div>
          </div>
        </div>
      </div>

      <!-- Column 2: Active Skill Stack & Doctrine Configuration -->
      <div class="builder-col">
        <div class="col-header">
          <span>2. ACTIVE SKILL STACK (<span id="stack-count-label">0</span>)</span>
          <button class="btn btn-sm" onclick="clearStack()">Clear All</button>
        </div>
        <div class="col-body">
          <div>
            <span class="form-label">🎖️ Operator Persona / Doctrine</span>
            <select id="builder-doctrine" class="form-select" onchange="compilePrompt()">
              <option value="oscp_operator">CARNAGE // OSCP Strike &amp; Tactical Advisor</option>
              <option value="redteam_stealth">Red Team // OPSEC, EDR Evasion &amp; Adversary Sim</option>
              <option value="bug_bounty">Bug Bounty // High-Impact Vulnerability Hunter</option>
              <option value="sop_mentor">SOP Generator // Lab Transcript → Exam SOP</option>
            </select>
          </div>

          <div>
            <span class="form-label">🎯 Primary Task / Objective</span>
            <input type="text" id="builder-objective" class="form-input" placeholder="e.g. Enumerate AD ACLs and escalate from svc_sql to Domain Admin" oninput="compilePrompt()">
          </div>

          <div>
            <span class="form-label">➕ Quick-Add Skill to Stack</span>
            <select id="quick-add-select" class="form-select" onchange="if(this.value){addToStack(this.value);this.value='';}">
              <option value="">-- Select a skill to add --</option>
            </select>
          </div>

          <div id="stack-items" style="display:flex;flex-direction:column;gap:8px;"></div>
        </div>
      </div>

      <!-- Column 3: Live Compiled System Prompt & Export -->
      <div class="builder-col">
        <div class="col-header">
          <span>3. COMPILED SYSTEM PROMPT / LLM CONTEXT</span>
          <div style="display:flex;gap:6px;">
            <select id="builder-format" class="mode-select" style="width:auto;padding:3px 8px;" onchange="compilePrompt()">
              <option value="xml_system">Claude XML System Prompt</option>
              <option value="consolidated_skill_md">Merged SKILL.md Bundle</option>
              <option value="claude_cli">Claude Code CLI Command</option>
            </select>
            <button class="btn btn-red btn-sm" onclick="copyCompiledPrompt()">📋 Copy Prompt</button>
            <button class="btn btn-sm" onclick="downloadCompiledPrompt()">💾 Download</button>
          </div>
        </div>

        <div class="token-meter">
          <div style="display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:11.5px;">
            <span>Estimated Tokens: <strong id="meter-tokens" style="color:var(--emerald)">0</strong> / 200,000 (<span id="meter-pct">0%</span>)</span>
            <span id="meter-chars" style="color:var(--text-3)">0 chars</span>
          </div>
          <div class="token-bar-bg">
            <div class="token-bar-fill" id="meter-bar"></div>
          </div>
        </div>

        <textarea id="compiled-output" class="prompt-preview" readonly placeholder="Add skills from the Arsenal or click a Tactical Loadout Preset on the left to compile your prompt..."></textarea>
      </div>

    </div>
  </div>

  <!-- ==================== VIEW 3: GLOBAL COMMAND SEARCH ==================== -->
  <div id="view-commands" class="view-panel" style="flex-direction:column;">
    <div style="padding:16px 22px;background:var(--bg-1);border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:center;">
      <input type="text" id="cmd-search-input" class="search-input" style="max-width:520px;" placeholder="Search 11,800+ commands & payloads (e.g. impacket, hashcat, bloodhound, ffuf, frida, msfvenom)..." onkeydown="if(event.key==='Enter')runCommandSearch()">
      <select id="cmd-cat-filter" class="form-select" style="width:200px;" onchange="runCommandSearch()">
        <option value="">All 23 Categories</option>
      </select>
      <button class="btn btn-red" onclick="runCommandSearch()">🔍 Search Commands</button>
      <span id="cmd-search-status" style="font-family:var(--font-mono);font-size:12px;color:var(--text-2);"></span>
    </div>
    <div id="cmd-results-stream" class="markdown-Stream"></div>
  </div>

  <!-- ==================== VIEW 4: MINDMAP & INSTALLER ==================== -->
  <div id="view-installer" class="view-panel">
    <div style="display:grid;grid-template-columns:440px 1fr;width:100%;height:100%;overflow:hidden;">
      <div class="builder-col">
        <div class="col-header">📦 ONE-CLICK SKILL INSTALLER &amp; EXPORTER</div>
        <div class="col-body">
          <p style="font-size:12.5px;color:var(--text-1);line-height:1.5;">
            Deploy <strong>claude-red</strong> skills directly from the in-memory Git Vault to your local Claude or Antigravity skill directories.
          </p>
          <div>
            <span class="form-label">Target Environment</span>
            <select id="install-target-preset" class="form-select" onchange="updateInstallPath()">
              <option value="claude">Claude Skills (~/.claude/skills/claude-red)</option>
              <option value="antigravity">Antigravity Skills (~/.gemini/antigravity/skills)</option>
              <option value="custom">Custom Directory Path</option>
            </select>
          </div>
          <div>
            <span class="form-label">Destination Path</span>
            <input type="text" id="install-custom-path" class="form-input" value="~/.claude/skills/claude-red">
          </div>
          <div>
            <span class="form-label">Category Filter (Optional)</span>
            <select id="install-category" class="form-select">
              <option value="">All 23 Categories (79 Skills)</option>
            </select>
          </div>
          <div style="display:flex;gap:8px;margin-top:6px;">
            <button class="btn btn-red" style="flex:1;justify-content:center;" onclick="runInstaller(false)">🚀 Install Skills</button>
            <button class="btn btn-emerald" style="flex:1;justify-content:center;" onclick="exportZipBundle()">🗜️ Export ZIP Bundle</button>
          </div>
          <pre id="install-log" style="background:#05070a;border:1px solid var(--border);padding:12px;border-radius:6px;font-family:var(--font-mono);font-size:11.5px;color:var(--text-1);white-space:pre-wrap;min-height:160px;">Ready.</pre>
        </div>
      </div>
      <div class="main-pane" style="overflow-y:auto;padding:24px;" id="mindmap-pane"></div>
    </div>
  </div>

</div>

<div id="toast"></div>

<script>
let STATE = {
  skills: [],
  categories: [],
  presets: [],
  activeCategory: 'all',
  selectedSkillName: null,
  currentSkillData: null,
  activeSubTab: 'methodology',
  checkedSections: new Set(),
  stack: [] // [{name, mode: 'full'|'commands_only'|'summary'|'sections', sections: []}]
};

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { t.style.display = 'none'; }, 2600);
}

function getTargetContext() {
  return {
    target: document.getElementById('g-target').value.trim(),
    lhost: document.getElementById('g-lhost').value.trim(),
    lport: document.getElementById('g-lport').value.trim(),
    domain: document.getElementById('g-domain').value.trim(),
    user: document.getElementById('g-user').value.trim(),
    auto_substitute: document.getElementById('g-autosub').checked,
    objective: document.getElementById('builder-objective') ? document.getElementById('builder-objective').value.trim() : '',
    recon_notes: document.getElementById('recon-input') ? document.getElementById('recon-input').value.trim() : ''
  };
}

function applyClientVars(str) {
  const ctx = getTargetContext();
  if (!ctx.auto_substitute) return str;
  let out = str;
  if (ctx.target) {
    out = out.replace(/\b10\.10\.10\.\d+\b/g, ctx.target)
             .replace(/<target(?:_ip)?>|\$TARGET\b|\$\{TARGET\}/gi, ctx.target);
  }
  if (ctx.lhost) {
    out = out.replace(/<attacker(?:_ip)?>|<lhost>|\$LHOST\b|\$\{LHOST\}/gi, ctx.lhost);
  }
  if (ctx.lport) {
    out = out.replace(/<lport>|\$LPORT\b|\$\{LPORT\}/gi, ctx.lport);
  }
  if (ctx.domain) {
    out = out.replace(/\bcorp\.local\b|\bdomain\.local\b|<domain>|\$DOMAIN\b/gi, ctx.domain);
  }
  if (ctx.user) {
    out = out.replace(/<user(?:name)?>|\$USER\b/gi, ctx.user);
  }
  return out;
}

function onGlobalVarChange() {
  if (STATE.currentSkillData) renderSkillDetail(STATE.currentSkillData);
  if (STATE.stack.length > 0) compilePrompt();
}

function switchView(viewName, btn) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('view-' + viewName).classList.add('active');
  if (btn) btn.classList.add('active');
  if (viewName === 'commands' && !window._cmdLoaded) {
    window._cmdLoaded = true;
    document.getElementById('cmd-search-input').value = 'impacket';
    runCommandSearch();
  }
}

async function initApp() {
  const res = await fetch('/api/skills');
  const data = await res.json();
  STATE.skills = data.skills;
  STATE.categories = data.categories;
  STATE.presets = data.presets;

  document.getElementById('nav-skill-count').textContent = data.skill_count;
  document.getElementById('nav-cmd-count').textContent = data.total_code_blocks.toLocaleString();
  document.getElementById('stat-load-ms').textContent = data.load_time_ms + 'ms';

  renderCategoryPills();
  renderSkillList();
  renderPresets();
  populateSelects();
  renderMindmapPane(data.mindmap_md);

  if (STATE.skills.length > 0) {
    selectSkill(STATE.skills[0].name);
  }
}

function renderCategoryPills() {
  const wrap = document.getElementById('category-pills');
  let html = `<button class="cat-pill ${STATE.activeCategory === 'all' ? 'active' : ''}" onclick="setCategory('all')">All (${STATE.skills.length})</button>`;
  for (const c of STATE.categories) {
    const active = STATE.activeCategory === c.id ? 'active' : '';
    html += `<button class="cat-pill ${active}" onclick="setCategory('${c.id}')">${c.icon} ${c.label} (${c.count})</button>`;
  }
  wrap.innerHTML = html;
}

function setCategory(catId) {
  STATE.activeCategory = catId;
  renderCategoryPills();
  renderSkillList();
}

function renderSkillList() {
  const q = document.getElementById('skill-filter').value.trim().toLowerCase();
  const listEl = document.getElementById('skill-list');
  const filtered = STATE.skills.filter(s => {
    if (STATE.activeCategory !== 'all' && s.category !== STATE.activeCategory) return false;
    if (!q) return true;
    return s.name.toLowerCase().includes(q) ||
           s.title.toLowerCase().includes(q) ||
           s.description.toLowerCase().includes(q) ||
           s.trigger_phrases.some(t => t.toLowerCase().includes(q));
  });

  listEl.innerHTML = filtered.map(s => {
    const isSel = s.name === STATE.selectedSkillName ? 'selected' : '';
    const inStack = STATE.stack.some(x => x.name === s.name);
    return `
      <div class="skill-item ${isSel}" onclick="selectSkill('${s.name}')">
        <div class="skill-item-top">
          <div class="skill-item-name">${s.category_icon} ${s.name}</div>
          <button class="btn btn-sm ${inStack ? 'btn-emerald' : ''}" onclick="event.stopPropagation();addToStack('${s.name}')">
            ${inStack ? '✓ Stacked' : '+ Stack'}
          </button>
        </div>
        <div class="skill-item-desc">${escapeHtml(s.description)}</div>
        <div class="skill-item-meta">
          <span>${s.category_label}</span>
          <span>~${s.token_est.toLocaleString()} tok · ${s.code_block_count} cmds</span>
        </div>
      </div>
    `;
  }).join('');
}

async function selectSkill(skillName) {
  STATE.selectedSkillName = skillName;
  STATE.checkedSections.clear();
  renderSkillList();
  const res = await fetch('/api/skill?name=' + encodeURIComponent(skillName));
  const skill = await res.json();
  STATE.currentSkillData = skill;
  renderSkillDetail(skill);
}

function renderSkillDetail(skill) {
  const pane = document.getElementById('skill-detail-pane');
  const inStack = STATE.stack.some(x => x.name === skill.name);
  const triggersHtml = (skill.trigger_phrases || []).slice(0, 10).map(t => `<span class="trigger-tag">${escapeHtml(t)}</span>`).join('');

  let bodyContent = '';
  if (STATE.activeSubTab === 'methodology') {
    bodyContent = `
      <div class="toc-rail">
        <div class="toc-title">
          <span>Sections (${skill.sections.length})</span>
          <button class="btn btn-sm btn-red" onclick="addCheckedSectionsToStack('${skill.name}')">+ Stack Checked</button>
        </div>
        ${skill.sections.map(sec => `
          <div class="toc-item" onclick="document.getElementById('${sec.id}').scrollIntoView({behavior:'smooth'})">
            <div class="toc-item-left">
              <input type="checkbox" onclick="event.stopPropagation();toggleSectionCheck('${sec.id}', this.checked)" ${STATE.checkedSections.has(sec.id) ? 'checked' : ''}>
              <span title="${escapeHtml(sec.title)}">${escapeHtml(sec.title)}</span>
            </div>
            <span class="toc-tok">${sec.token_est}t</span>
          </div>
        `).join('')}
      </div>
      <div class="markdown-Stream">
        ${skill.sections.map(sec => `
          <div class="sec-card" id="${sec.id}">
            <div class="sec-card-header">
              <div class="sec-card-title">## ${escapeHtml(sec.title)}</div>
              <div style="display:flex;gap:8px;align-items:center;">
                <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-3);">~${sec.token_est} tokens · ${sec.code_count} code blocks</span>
                <button class="btn btn-sm" onclick="addSingleSectionToStack('${skill.name}', '${sec.id}')">+ Add Section to Prompt</button>
              </div>
            </div>
            <div class="md-content">${renderMarkdown(applyClientVars(sec.content))}</div>
          </div>
        `).join('')}
      </div>
    `;
  } else if (STATE.activeSubTab === 'commands') {
    bodyContent = `
      <div class="markdown-Stream">
        ${skill.code_blocks.map((cb, idx) => {
          const subCode = applyClientVars(cb.code);
          return `
            <div class="code-box">
              <div class="code-box-bar">
                <span><strong>#${idx + 1}</strong> · ${escapeHtml(cb.section)} <span style="color:var(--amber)">[${escapeHtml(cb.lang)}]</span></span>
                <button class="btn btn-sm" onclick="copyText(${JSON.stringify(subCode).replace(/"/g, '&quot;')})">📋 Copy Command</button>
              </div>
              <pre>${escapeHtml(subCode)}</pre>
            </div>
          `;
        }).join('')}
      </div>
    `;
  } else {
    bodyContent = `
      <div class="markdown-Stream">
        <div class="code-box">
          <div class="code-box-bar">
            <span>Raw SKILL.md (${skill.char_count.toLocaleString()} bytes)</span>
            <button class="btn btn-sm" onclick="copyText(STATE.currentSkillData.raw)">📋 Copy Raw SKILL.md</button>
          </div>
          <pre>${escapeHtml(applyClientVars(skill.raw))}</pre>
        </div>
      </div>
    `;
  }

  pane.innerHTML = `
    <div class="skill-header">
      <div class="skill-header-top">
        <div>
          <div class="skill-title">
            <span>${skill.category_icon} ${escapeHtml(skill.title)}</span>
            <span class="trigger-tag" style="color:var(--emerald);border-color:var(--emerald)">~${skill.token_est.toLocaleString()} tokens</span>
            <span class="trigger-tag" style="color:var(--amber)">${escapeHtml(skill.source_mode)}</span>
          </div>
          <div class="skill-path">${escapeHtml(skill.path)}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn ${inStack ? 'btn-emerald' : 'btn-red'}" onclick="addToStack('${skill.name}')">
            ${inStack ? '✓ In Prompt Builder Stack' : '⚡ + Add to Prompt Builder'}
          </button>
          <button class="btn" onclick="copyText(applyClientVars(STATE.currentSkillData.raw))">📋 Copy Full SKILL.md</button>
          <button class="btn" onclick="copyText('cat ' + STATE.currentSkillData.path + ' | claude --system-file -')">💻 Copy Claude CLI</button>
        </div>
      </div>
      <div class="skill-desc-box">${escapeHtml(skill.description)}</div>
      ${triggersHtml ? `<div class="trigger-row"><span style="font-size:11px;color:var(--text-3);font-family:var(--font-mono);">Triggers:</span>${triggersHtml}</div>` : ''}
    </div>

    <div class="sub-tabs">
      <button class="sub-tab ${STATE.activeSubTab === 'methodology' ? 'active' : ''}" onclick="setSubTab('methodology')">📖 Structured Methodology (${skill.section_count})</button>
      <button class="sub-tab ${STATE.activeSubTab === 'commands' ? 'active' : ''}" onclick="setSubTab('commands')">💻 Extracted Commands &amp; Payloads (${skill.code_block_count})</button>
      <button class="sub-tab ${STATE.activeSubTab === 'raw' ? 'active' : ''}" onclick="setSubTab('raw')">📄 Raw SKILL.md</button>
    </div>

    <div class="skill-body-wrap">${bodyContent}</div>
  `;
}

function setSubTab(tab) {
  STATE.activeSubTab = tab;
  if (STATE.currentSkillData) renderSkillDetail(STATE.currentSkillData);
}

function toggleSectionCheck(secId, checked) {
  if (checked) STATE.checkedSections.add(secId);
  else STATE.checkedSections.delete(secId);
}

function addSingleSectionToStack(skillName, secId) {
  const existing = STATE.stack.find(x => x.name === skillName);
  if (existing) {
    existing.mode = 'sections';
    if (!existing.sections.includes(secId)) existing.sections.push(secId);
  } else {
    STATE.stack.push({ name: skillName, mode: 'sections', sections: [secId] });
  }
  updateStackUI();
  showToast(`Added section to Prompt Builder stack!`);
}

function addCheckedSectionsToStack(skillName) {
  if (STATE.checkedSections.size === 0) {
    showToast('Check one or more sections in the left rail first!');
    return;
  }
  const secs = Array.from(STATE.checkedSections);
  const existing = STATE.stack.find(x => x.name === skillName);
  if (existing) {
    existing.mode = 'sections';
    existing.sections = Array.from(new Set([...existing.sections, ...secs]));
  } else {
    STATE.stack.push({ name: skillName, mode: 'sections', sections: secs });
  }
  updateStackUI();
  showToast(`Added ${secs.length} section(s) from ${skillName} to Prompt Builder!`);
}

/* -------------------- Prompt Builder Functions -------------------- */
function renderPresets() {
  const el = document.getElementById('preset-list');
  el.innerHTML = STATE.presets.map(p => `
    <div class="preset-card" onclick="loadPreset('${p.id}')">
      <div class="preset-card-title">${escapeHtml(p.name)}</div>
      <div class="preset-card-desc">${escapeHtml(p.description)}</div>
    </div>
  `).join('');
}

function populateSelects() {
  const qa = document.getElementById('quick-add-select');
  qa.innerHTML = `<option value="">-- Select a skill to add (${STATE.skills.length}) --</option>` +
    STATE.skills.map(s => `<option value="${s.name}">${s.category_icon} ${s.name} (~${s.token_est} tok)</option>`).join('');

  const catHtml = `<option value="">All 23 Categories (${STATE.skills.length} Skills)</option>` +
    STATE.categories.map(c => `<option value="${c.id}">${c.icon} ${c.label} (${c.count})</option>`).join('');
  document.getElementById('cmd-cat-filter').innerHTML = catHtml;
  document.getElementById('install-category').innerHTML = catHtml;
}

function loadPreset(presetId) {
  const p = STATE.presets.find(x => x.id === presetId);
  if (!p) return;
  STATE.stack = p.skills.map(s => ({ name: s.name, mode: s.mode, sections: [] }));
  document.getElementById('builder-doctrine').value = p.doctrine;
  updateStackUI();
  showToast(`Loaded preset: ${p.name}`);
}

function addToStack(skillName, defaultMode = 'commands_only') {
  const idx = STATE.stack.findIndex(x => x.name === skillName);
  if (idx >= 0) {
    showToast(`${skillName} is already in the Prompt Builder stack`);
    return;
  }
  const s = STATE.skills.find(x => x.name === skillName);
  // Default huge skills (>25k tokens) to commands_only so user doesn't accidentally blow context
  const mode = (s && s.token_est > 25000) ? 'commands_only' : 'full';
  STATE.stack.push({ name: skillName, mode: mode, sections: [] });
  updateStackUI();
  renderSkillList();
  if (STATE.currentSkillData && STATE.currentSkillData.name === skillName) {
    renderSkillDetail(STATE.currentSkillData);
  }
  showToast(`Added ${skillName} to Prompt Builder`);
}

function removeFromStack(skillName) {
  STATE.stack = STATE.stack.filter(x => x.name !== skillName);
  updateStackUI();
  renderSkillList();
}

function clearStack() {
  STATE.stack = [];
  updateStackUI();
  renderSkillList();
}

function setStackMode(skillName, mode) {
  const item = STATE.stack.find(x => x.name === skillName);
  if (item) {
    item.mode = mode;
    compilePrompt();
  }
}

function updateStackUI() {
  document.getElementById('nav-stack-count').textContent = STATE.stack.length;
  document.getElementById('stack-count-label').textContent = STATE.stack.length;
  const wrap = document.getElementById('stack-items');

  if (STATE.stack.length === 0) {
    wrap.innerHTML = `<div style="padding:18px;border:1px dashed var(--border);border-radius:6px;color:var(--text-3);font-size:12px;text-align:center;">No skills stacked yet. Select a Loadout Preset on the left, paste Nmap output, or click "+ Stack" on any skill.</div>`;
    document.getElementById('compiled-output').value = '';
    document.getElementById('meter-tokens').textContent = '0';
    document.getElementById('meter-pct').textContent = '0%';
    document.getElementById('meter-bar').style.width = '0%';
    return;
  }

  wrap.innerHTML = STATE.stack.map(item => {
    const s = STATE.skills.find(x => x.name === item.name) || { title: item.name, token_est: 0, category_icon: '📄' };
    return `
      <div class="stack-card">
        <div class="stack-card-top">
          <span class="stack-card-name">${s.category_icon} ${item.name}</span>
          <button class="btn btn-sm" onclick="removeFromStack('${item.name}')">✕</button>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <select class="mode-select" onchange="setStackMode('${item.name}', this.value)">
            <option value="full" ${item.mode === 'full' ? 'selected' : ''}>Full Methodology (~${s.token_est.toLocaleString()} tok)</option>
            <option value="commands_only" ${item.mode === 'commands_only' ? 'selected' : ''}>Commands &amp; Checklists Only (~60% smaller)</option>
            <option value="summary" ${item.mode === 'summary' ? 'selected' : ''}>Quick Workflow Summary (~85% smaller)</option>
            ${item.sections && item.sections.length ? `<option value="sections" ${item.mode === 'sections' ? 'selected' : ''}>Checked Sections (${item.sections.length})</option>` : ''}
          </select>
        </div>
      </div>
    `;
  }).join('');

  compilePrompt();
}

async function compilePrompt() {
  if (STATE.stack.length === 0) return;
  const payload = {
    skills: STATE.stack,
    doctrine: document.getElementById('builder-doctrine').value,
    format: document.getElementById('builder-format').value,
    context: getTargetContext()
  };
  const res = await fetch('/api/compile-prompt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  document.getElementById('compiled-output').value = data.prompt;
  document.getElementById('meter-tokens').textContent = data.token_est.toLocaleString();
  document.getElementById('meter-pct').textContent = data.context_pct_200k + '%';
  document.getElementById('meter-chars').textContent = data.char_count.toLocaleString() + ' chars';
  document.getElementById('meter-bar').style.width = Math.min(100, data.context_pct_200k) + '%';
}

async function runReconMatcher() {
  const text = document.getElementById('recon-input').value.trim();
  if (!text) {
    showToast('Paste Nmap scan output, ports, or target notes first!');
    return;
  }
  const res = await fetch('/api/recommend', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recon_text: text })
  });
  const data = await res.json();
  const box = document.getElementById('recon-results');
  if (!data.recommendations || data.recommendations.length === 0) {
    box.innerHTML = `<div style="font-size:12px;color:var(--text-2);">No specific service triggers matched — added fast web/host triage.</div>`;
    return;
  }
  for (const r of data.recommendations) {
    if (!STATE.stack.some(x => x.name === r.name)) {
      STATE.stack.push({ name: r.name, mode: 'commands_only', sections: [] });
    }
  }
  updateStackUI();
  box.innerHTML = data.recommendations.map(r => `
    <div style="background:var(--bg-0);border:1px solid var(--emerald);border-radius:5px;padding:7px 10px;font-size:11.5px;">
      <strong style="color:var(--emerald);font-family:var(--font-mono);">✓ ${r.name}</strong>
      <div style="color:var(--text-2);margin-top:2px;">${escapeHtml(r.reason)}</div>
    </div>
  `).join('');
  showToast(`Stacked ${data.recommendations.length} recommended skill(s)!`);
}

function copyCompiledPrompt() {
  const val = document.getElementById('compiled-output').value;
  if (!val) return;
  copyText(val);
}

function downloadCompiledPrompt() {
  const val = document.getElementById('compiled-output').value;
  if (!val) return;
  const blob = new Blob([val], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'claude-red-operator-prompt.md';
  a.click();
}

/* -------------------- Global Command Search -------------------- */
async function runCommandSearch() {
  const q = document.getElementById('cmd-search-input').value.trim();
  const cat = document.getElementById('cmd-cat-filter').value;
  const statusEl = document.getElementById('cmd-search-status');
  statusEl.textContent = 'Searching...';
  const res = await fetch('/api/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: q, category: cat })
  });
  const data = await res.json();
  statusEl.textContent = `Found ${data.results.length} command blocks (showing top ${data.results.length})`;
  const stream = document.getElementById('cmd-results-stream');
  stream.innerHTML = data.results.map(r => {
    const codeSub = applyClientVars(r.code);
    return `
      <div class="code-box">
        <div class="code-box-bar">
          <span>
            <strong style="color:var(--red);cursor:pointer;" onclick="selectSkill('${r.skill}');switchView('explorer', document.querySelectorAll('.nav-tab')[0])">${r.skill}</strong>
            · ${escapeHtml(r.section)} <span style="color:var(--amber)">[${escapeHtml(r.lang)}]</span>
          </span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-sm" onclick="addToStack('${r.skill}')">+ Stack Skill</button>
            <button class="btn btn-sm btn-red" onclick="copyText(${JSON.stringify(codeSub).replace(/"/g, '&quot;')})">📋 Copy</button>
          </div>
        </div>
        <pre>${escapeHtml(codeSub)}</pre>
      </div>
    `;
  }).join('');
}

/* -------------------- Installer & Mindmap -------------------- */
function updateInstallPath() {
  const preset = document.getElementById('install-target-preset').value;
  const input = document.getElementById('install-custom-path');
  if (preset === 'claude') input.value = '~/.claude/skills/claude-red';
  else if (preset === 'antigravity') input.value = '~/.gemini/antigravity/skills';
}

async function runInstaller() {
  const target = document.getElementById('install-custom-path').value.trim();
  const category = document.getElementById('install-category').value;
  const logEl = document.getElementById('install-log');
  logEl.textContent = 'Installing skills from Git Vault...';
  const res = await fetch('/api/install', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, category })
  });
  const data = await res.json();
  logEl.textContent = data.message;
  showToast(`Installed ${data.installed_count} skill(s)!`);
}

function exportZipBundle() {
  const category = document.getElementById('install-category').value;
  window.location.href = '/api/export-zip?category=' + encodeURIComponent(category);
}

function renderMindmapPane(md) {
  const pane = document.getElementById('mindmap-pane');
  pane.innerHTML = `
    <div class="sec-card">
      <div class="sec-card-header">
        <div class="sec-card-title">🗺️ CLAUDE-RED // MITRE ATT&amp;CK &amp; OWASP WSTG COVERAGE MATRIX</div>
      </div>
      <div class="md-content">${renderMarkdown(md)}</div>
    </div>
  `;
}

/* -------------------- Utilities & Markdown Renderer -------------------- */
function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => showToast('Copied to clipboard!'));
}

function renderMarkdown(md) {
  if (!md) return '';
  const codeBlocks = [];
  let text = md.replace(/```([a-zA-Z0-9_+-]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    const clean = code.trim();
    codeBlocks.push({ lang: lang || 'bash', code: clean });
    return `@@CODEBLOCK_${idx}@@`;
  });

  const lines = text.split('\n');
  let out = [];
  for (let line of lines) {
    const trimmed = line.trim();
    if (/^@@CODEBLOCK_(\d+)@@$/.test(trimmed)) {
      const idx = parseInt(trimmed.match(/^@@CODEBLOCK_(\d+)@@$/)[1], 10);
      const cb = codeBlocks[idx];
      out.push(`
        <div class="code-box">
          <div class="code-box-bar">
            <span>${escapeHtml(cb.lang)}</span>
            <button class="btn btn-sm" onclick="copyText(${JSON.stringify(cb.code).replace(/"/g, '&quot;')})">📋 Copy</button>
          </div>
          <pre>${escapeHtml(cb.code)}</pre>
        </div>
      `);
      continue;
    }
    if (line.startsWith('### ')) {
      out.push(`<h3>${formatInline(line.slice(4))}</h3>`);
    } else if (line.startsWith('## ')) {
      continue; // Already rendered in card header
    } else if (line.startsWith('# ')) {
      out.push(`<h3>${formatInline(line.slice(2))}</h3>`);
    } else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      out.push(`<li>${formatInline(trimmed.slice(2))}</li>`);
    } else if (/^\d+\.\s+/.test(trimmed)) {
      out.push(`<li>${formatInline(trimmed)}</li>`);
    } else if (trimmed === '---') {
      out.push(`<hr style="border:none;border-top:1px solid var(--border);margin:12px 0;">`);
    } else if (trimmed.length > 0) {
      out.push(`<p>${formatInline(line)}</p>`);
    }
  }
  return out.join('\n');
}

function formatInline(str) {
  let s = escapeHtml(str);
  s = s.replace(/`([^`]+)`/g, '<code class="inline">$1</code>');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  return s;
}

window.addEventListener('DOMContentLoaded', initApp);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP Server Handler
# ---------------------------------------------------------------------------
class ClaudeRedRequestHandler(BaseHTTPRequestHandler):
    repo: SkillRepository = None  # type: ignore

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # Keep console clean

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            raw = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if path == "/api/skills":
            self._send_json(self.repo.get_index_payload())
            return

        if path == "/api/skill":
            name = (qs.get("name") or [""])[0]
            skill = self.repo.skills_by_name.get(name)
            if not skill:
                self._send_json({"error": f"Skill '{name}' not found"}, 404)
                return
            self._send_json(skill)
            return

        if path == "/api/export-zip":
            cat = (qs.get("category") or [""])[0].strip()
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in self.repo.skills_by_name.values():
                    if cat and s["category"] != cat:
                        continue
                    zf.writestr(f"claude-red/{s['path']}", s["raw"])
            raw_zip = buf.getvalue()
            fname = f"claude-red-{cat or 'all-79-skills'}.zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(raw_zip)))
            self.end_headers()
            self.wfile.write(raw_zip)
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/compile-prompt":
            result = compile_operator_prompt(self.repo, body)
            self._send_json(result)
            return

        if path == "/api/recommend":
            recon_text = (body.get("recon_text") or "").lower()
            matched: dict[str, str] = {}
            for rule in RECON_SIGNALS:
                if any(re.search(pat, recon_text, re.I) for pat in rule["patterns"]):
                    for sname in rule["skills"]:
                        if sname in self.repo.skills_by_name and sname not in matched:
                            matched[sname] = rule["reason"]
            # Also check direct trigger phrase matches across all skills
            for s in self.repo.skills_by_name.values():
                if s["name"] in matched:
                    continue
                for trig in s["trigger_phrases"]:
                    if len(trig) >= 4 and trig.lower() in recon_text:
                        matched[s["name"]] = f"Matched skill trigger phrase: '{trig}'"
                        break
            recs = [{"name": k, "reason": v} for k, v in list(matched.items())[:8]]
            self._send_json({"recommendations": recs})
            return

        if path == "/api/search":
            q = (body.get("query") or "").strip().lower()
            cat = (body.get("category") or "").strip()
            results = []
            for s in self.repo.skills_by_name.values():
                if cat and s["category"] != cat:
                    continue
                for cb in s["code_blocks"]:
                    if (
                        not q
                        or q in cb["code"].lower()
                        or q in cb["section"].lower()
                        or q in s["name"].lower()
                    ):
                        results.append(
                            {
                                "skill": s["name"],
                                "category": s["category"],
                                "lang": cb["lang"],
                                "section": cb["section"],
                                "code": cb["code"],
                            }
                        )
                        if len(results) >= 120:
                            break
                if len(results) >= 120:
                    break
            self._send_json({"results": results})
            return

        if path == "/api/install":
            target_raw = (body.get("target") or "~/.claude/skills/claude-red").strip()
            cat = (body.get("category") or "").strip()
            target_dir = Path(os.path.expanduser(target_raw)).resolve()
            installed = 0
            skipped_defender = 0
            logs = [f"Target Directory: {target_dir}"]
            for s in sorted(self.repo.skills_by_name.values(), key=lambda x: x["name"]):
                if cat and s["category"] != cat:
                    continue
                dest_file = target_dir / s["category"] / s["name"] / "SKILL.md"
                try:
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    dest_file.write_text(s["raw"], encoding="utf-8", newline="\n")
                    installed += 1
                except OSError as exc:
                    skipped_defender += 1
                    logs.append(f"  [!] OS/Defender blocked write for {s['name']}: {exc}")
            logs.append(f"\nDone! Installed {installed} skill(s) to {target_dir}.")
            if skipped_defender:
                logs.append(
                    f"Note: {skipped_defender} file(s) were blocked by Windows Defender on disk write (use Export ZIP or the in-memory Prompt Builder for those)."
                )
            self._send_json(
                {
                    "installed_count": installed,
                    "skipped_count": skipped_defender,
                    "message": "\n".join(logs),
                }
            )
            return

        self._send_json({"error": "Unknown endpoint"}, 404)


def main() -> int:
    parser = argparse.ArgumentParser(description="CLAUDE-RED Tactical GUI & Prompt Builder")
    parser.add_argument("--port", type=int, default=8765, help="Local port (default: 8765)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind address")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    args = parser.parse_args()

    print("[*] Initializing CLAUDE-RED Tactical Operator Console...")
    repo = SkillRepository(REPO_DIR)
    print(
        f"[+] Loaded {len(repo.skills_by_name)} skills across {len(CATEGORY_META)} categories in {repo.load_time_ms}ms (Hybrid Git-Vault active)"
    )

    ClaudeRedRequestHandler.repo = repo
    server = ThreadingHTTPServer((args.host, args.port), ClaudeRedRequestHandler)
    url = f"http://{args.host}:{args.port}"
    print(f"[+] CLAUDE-RED Console live at: {url}")

    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down CLAUDE-RED Console.")
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
