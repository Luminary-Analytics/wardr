"""Three-tier AI protection: Always-on Radar (T1), Redacted Cloud Offload (T2), and Local Heavy AI (T3)."""

from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

from . import local_ai, reporting


_CONFIG_FILE = "ai-tiers.json"
_CLOUD_TIMEOUT = 35
_LOCAL_TIMEOUT = 75
_MAX_RESPONSE_BYTES = 128 * 1024

TIERS = ("radar", "cloud", "local")

CLOUD_PRESETS = {
    "huggingface": {
        "id": "huggingface",
        "label": "Hugging Face Inference (Free Tier)",
        "endpoint": "https://router.huggingface.co/v1/chat/completions",
        "default_model": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct",
        "note": "Runs Cisco Foundation-Sec-8B in the cloud with zero local CPU or RAM load.",
    },
    "groq": {
        "id": "groq",
        "label": "Groq Cloud (Free Tier)",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "default_model": "llama-3.3-70b-versatile",
        "note": "Ultra-fast free-tier cloud inference for instant threat triage with zero local CPU load.",
    },
    "openrouter": {
        "id": "openrouter",
        "label": "OpenRouter (Free Open-Weight Models)",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "default_model": "qwen/qwen3-8b:free",
        "note": "Free open-source models via OpenRouter — offloads analysis away from your CPU.",
    },
    "custom": {
        "id": "custom",
        "label": "Custom HTTPS OpenAI-Compatible API",
        "endpoint": "",
        "default_model": "fdtn-ai/Foundation-Sec-1.1-8B-Instruct",
        "note": "Bring any trusted HTTPS OpenAI-compatible inference endpoint.",
    },
}

LOCAL_PROFILES = {
    "foundation-sec-8b": {
        "id": "foundation-sec-8b",
        "label": "Cisco Foundation-Sec 1.1 (8B)",
        "ollama_tag": "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF",
        "license": "Apache-2.0",
        "size_label": "~4.9 GB",
        "min_ram_gb": 12,
        "role": "Dedicated cybersecurity model",
        "summary": "Purpose-trained by Cisco Foundation AI on CVEs, threat intelligence, and defensive triage.",
    },
    "qwen3-4b": {
        "id": "qwen3-4b",
        "label": "Qwen3 4B",
        "ollama_tag": "qwen3:4b",
        "license": "Apache-2.0",
        "size_label": "~2.5 GB",
        "min_ram_gb": 8,
        "role": "Lightweight local triage",
        "summary": "Fast structured security reasoning that fits comfortably on 8 GB laptops.",
    },
    "inkling-2-mini": {
        "id": "inkling-2-mini",
        "label": "Inkling 2 Mini",
        "ollama_tag": "inkling-2-mini",
        "license": "Apache-2.0",
        "size_label": "~20 GB",
        "min_ram_gb": 32,
        "role": "Deep workstation analysis",
        "summary": "Looped-transformer MoE (26.4B total / 3.4B active) with 1M context for deep offline audits.",
    },
    "qwen2.5-1.5b": {
        "id": "qwen2.5-1.5b",
        "label": "Qwen 2.5 1.5B (Ultra-Light)",
        "ollama_tag": local_ai.MODEL,
        "license": "Apache-2.0",
        "size_label": "~1.0 GB",
        "min_ram_gb": 4,
        "role": "Minimal footprint fallback",
        "summary": "Wardr's digest-pinned 1.5B fallback for low-memory devices.",
    },
}

_TRIAGE_SYSTEM_PROMPT = (
    "You are Wardr's defensive cybersecurity analyst. "
    "You receive a redacted device security summary (never invent threats or claims outside the input). "
    "Return ONLY valid JSON with keys: "
    '"summary" (string, max 220 chars, plain English for a non-technical user), '
    '"threat_verdict" (string, max 160 chars, clear statement on active threats right now), '
    '"top_actions" (array of 1 to 3 concise plain-English next steps, each max 140 chars). '
    "Do not include markdown fences or extra keys."
)


class AITierError(RuntimeError):
    """A Tier 2 cloud or Tier 3 local AI operation could not complete."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_CACHED_RAM_GB: int | None = None
_RAM_DETECTED = False


def detect_ram_gb() -> int | None:
    """Best-effort detection of total physical memory in GiB (cached once per process)."""
    global _CACHED_RAM_GB, _RAM_DETECTED
    if _RAM_DETECTED:
        return _CACHED_RAM_GB
    system = platform.system()
    detected = None
    try:
        if system == "Darwin":
            out = subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=2, text=True).strip()
            detected = max(1, round(int(out) / (1024 ** 3)))
        elif system == "Linux":
            with open("/proc/meminfo", encoding="ascii") as handle:
                for line in handle:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        detected = max(1, round(kb / (1024 ** 2)))
                        break
        elif system == "Windows":
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MemoryStatus()
            stat.dwLength = ctypes.sizeof(stat)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                detected = max(1, round(stat.ullTotalPhys / (1024 ** 3)))
    except Exception:
        detected = None
    _CACHED_RAM_GB = detected
    _RAM_DETECTED = True
    return detected


def recommended_local_profile(ram_gb: int | None) -> str:
    if ram_gb is None:
        return "qwen3-4b"
    if ram_gb >= 12:
        return "foundation-sec-8b"
    if ram_gb >= 8:
        return "qwen3-4b"
    return "qwen2.5-1.5b"


def default_config(ram_gb: int | None = None) -> dict:
    preset = CLOUD_PRESETS["huggingface"]
    return {
        "active_tier": "radar",
        "cloud_preset": preset["id"],
        "cloud_endpoint": preset["endpoint"],
        "cloud_model": preset["default_model"],
        "cloud_api_key": "",
        "local_profile": recommended_local_profile(ram_gb),
    }


def _config_path(state_dir: Path) -> Path:
    return Path(state_dir) / _CONFIG_FILE


def load_config(state_dir: Path) -> dict:
    base = default_config(detect_ram_gb())
    path = _config_path(state_dir)
    if not path.is_file():
        return base
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return base
    except (OSError, ValueError):
        return base
    if raw.get("active_tier") in TIERS:
        base["active_tier"] = raw["active_tier"]
    if raw.get("cloud_preset") in CLOUD_PRESETS:
        base["cloud_preset"] = raw["cloud_preset"]
    if isinstance(raw.get("cloud_endpoint"), str) and raw["cloud_endpoint"].strip():
        base["cloud_endpoint"] = raw["cloud_endpoint"].strip()
    if isinstance(raw.get("cloud_model"), str) and raw["cloud_model"].strip():
        base["cloud_model"] = raw["cloud_model"].strip()[:160]
    if isinstance(raw.get("cloud_api_key"), str):
        base["cloud_api_key"] = raw["cloud_api_key"].strip()[:256]
    if raw.get("local_profile") in LOCAL_PROFILES:
        base["local_profile"] = raw["local_profile"]
    return base


def _resolve_public_ip(host: str, port: int) -> str:
    """Resolve host once and verify every address is globally routable (prevents DNS rebinding & SSRF)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AITierError(f"Could not resolve Tier 2 cloud AI host ({host}).") from exc
    if not infos:
        raise AITierError(f"Could not resolve Tier 2 cloud AI host ({host}).")
    chosen_ip = None
    for family, _type, _proto, _canon, sockaddr in infos:
        raw_ip = sockaddr[0]
        try:
            parsed_ip = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise AITierError("Tier 2 cloud AI resolved to an invalid IP address.") from exc
        effective = getattr(parsed_ip, "ipv4_mapped", None) or parsed_ip
        if (
            not effective.is_global
            or effective.is_loopback
            or effective.is_private
            or effective.is_link_local
            or effective.is_multicast
            or effective.is_reserved
            or effective.is_unspecified
        ):
            raise AITierError("Tier 2 cloud AI endpoint resolved to a non-public or local network address.")
        if chosen_ip is None:
            chosen_ip = str(parsed_ip)
    assert chosen_ip is not None
    return chosen_ip


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection pinned to a pre-validated IP while preserving TLS SNI and Host verification."""

    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _validate_cloud_endpoint(url: str) -> tuple[str, int, str]:
    if any(ch in url for ch in ("\r", "\n", "\x00")):
        raise ValueError("Cloud AI endpoint cannot contain control characters.")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Cloud AI endpoint must be a valid HTTPS URL without embedded credentials.")
    host = parsed.hostname.lower().rstrip(".")
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("Cloud AI endpoint cannot target loopback or local-network addresses.")
    try:
        ip = ipaddress.ip_address(host)
        effective = getattr(ip, "ipv4_mapped", None) or ip
        if not effective.is_global:
            raise ValueError("Cloud AI endpoint must resolve to a public internet host.")
    except ValueError as exc:
        if "public internet host" in str(exc):
            raise
    # Reject shorthand/numeric IP literals like 127.1 or 2130706433
    if all(part.isdigit() or part.startswith("0x") for part in host.split(".") if part):
        raise ValueError("Cloud AI endpoint must use a valid public hostname or canonical IP.")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, port, path


def save_config(state_dir: Path, update: dict) -> dict:
    current = load_config(state_dir)
    if "active_tier" in update:
        if update["active_tier"] not in TIERS:
            raise ValueError("Choose radar, cloud, or local protection tier.")
        current["active_tier"] = update["active_tier"]
    if "cloud_preset" in update:
        preset_id = update["cloud_preset"]
        if preset_id not in CLOUD_PRESETS:
            raise ValueError("Choose a supported cloud provider preset.")
        current["cloud_preset"] = preset_id
        preset = CLOUD_PRESETS[preset_id]
        if preset_id != "custom":
            current["cloud_endpoint"] = preset["endpoint"]
            if not update.get("cloud_model"):
                current["cloud_model"] = preset["default_model"]
    if "cloud_endpoint" in update and isinstance(update["cloud_endpoint"], str):
        endpoint = update["cloud_endpoint"].strip()
        if endpoint:
            _validate_cloud_endpoint(endpoint)
            current["cloud_endpoint"] = endpoint
    if "cloud_model" in update and isinstance(update["cloud_model"], str):
        model = update["cloud_model"].strip()
        if not model or len(model) > 160:
            raise ValueError("Provide a valid cloud model identifier.")
        current["cloud_model"] = model
    if "cloud_api_key" in update and isinstance(update["cloud_api_key"], str):
        key = update["cloud_api_key"].strip()
        if len(key) > 256 or any(ord(c) < 32 for c in key):
            raise ValueError("API key is invalid or exceeds maximum allowed length.")
        current["cloud_api_key"] = key
    if update.get("clear_api_key") is True:
        current["cloud_api_key"] = ""
    if "local_profile" in update:
        if update["local_profile"] not in LOCAL_PROFILES:
            raise ValueError("Choose a supported local security model profile.")
        current["local_profile"] = update["local_profile"]

    if current["active_tier"] == "cloud":
        _validate_cloud_endpoint(current["cloud_endpoint"])

    directory = Path(state_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=".ai-tiers-", suffix=".json")
    staging = Path(name)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(current, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        staging.replace(_config_path(directory))
    finally:
        staging.unlink(missing_ok=True)
    return current


def _ollama_installed_models() -> tuple[bool, list[str]]:
    try:
        response = local_ai._request("/api/tags", timeout=2, limit=512 * 1024)
    except local_ai.LocalAIError:
        return False, []
    raw_models = response.get("models")
    if not isinstance(raw_models, list):
        return False, []
    names = []
    for entry in raw_models:
        if isinstance(entry, dict):
            name = entry.get("model") or entry.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return True, names


def _tag_installed(tag: str, installed: list[str]) -> bool:
    if tag in installed:
        return True
    base = tag.split(":", 1)[0]
    return any(item == tag or item == f"{tag}:latest" or (":" not in tag and item.split(":", 1)[0] == base) for item in installed)


def public_status(state_dir: Path, *, offline: bool = False) -> dict:
    """Return safe, customer-facing status for all 3 protection tiers (never exposes API keys)."""
    ram_gb = detect_ram_gb()
    cfg = load_config(state_dir)
    rec = recommended_local_profile(ram_gb)
    ollama_available, installed = _ollama_installed_models()

    local_profile = LOCAL_PROFILES[cfg["local_profile"]]
    local_ready = ollama_available and _tag_installed(local_profile["ollama_tag"], installed)

    has_key = bool(cfg["cloud_api_key"])
    key_hint = f"…{cfg['cloud_api_key'][-4:]}" if len(cfg["cloud_api_key"]) >= 4 else ""
    cloud_ready = (not offline) and has_key and bool(cfg["cloud_endpoint"]) and bool(cfg["cloud_model"])

    profiles = [
        {
            **profile,
            "installed": ollama_available and _tag_installed(profile["ollama_tag"], installed),
            "recommended": profile["id"] == rec,
            "fits_ram": ram_gb is None or ram_gb >= profile["min_ram_gb"],
        }
        for profile in LOCAL_PROFILES.values()
    ]

    return {
        "active_tier": cfg["active_tier"],
        "host_ram_gb": ram_gb,
        "recommended_local_profile": rec,
        "offline": offline,
        "tier1": {
            "id": "radar",
            "label": "Tier 1 · Always-On Local Radar",
            "ready": True,
            "cpu_impact": "Minimal (<30 MB RAM, 0% GPU)",
            "summary": "Deterministic continuous scanning for network listeners, persistence changes, file integrity, and OS security posture.",
        },
        "tier2": {
            "id": "cloud",
            "label": "Tier 2 · Free Cloud AI Offload",
            "ready": cloud_ready,
            "enabled": cfg["active_tier"] == "cloud",
            "preset": cfg["cloud_preset"],
            "endpoint": cfg["cloud_endpoint"],
            "model": cfg["cloud_model"],
            "has_api_key": has_key,
            "key_hint": key_hint,
            "cpu_impact": "Zero local CPU/RAM load",
            "privacy_note": "Strictly redacted locally (hostnames, usernames, paths, IPs, and secrets stripped before sending).",
            "presets": list(CLOUD_PRESETS.values()),
        },
        "tier3": {
            "id": "local",
            "label": "Tier 3 · Heavy Local AI (100% Offline)",
            "ready": local_ready,
            "enabled": cfg["active_tier"] == "local",
            "ollama_available": ollama_available,
            "profile": cfg["local_profile"],
            "model_label": local_profile["label"],
            "ollama_tag": local_profile["ollama_tag"],
            "cpu_impact": f"Uses local RAM ({local_profile['size_label']})",
            "profiles": profiles,
        },
    }


def _build_redacted_prompt(host: dict, posture: dict, checks: list, threats: dict) -> tuple[str, int]:
    total_redactions = 0

    def clean(value: str) -> str:
        nonlocal total_redactions
        text, counts = reporting.redact_text(str(value or ""), host=host)
        total_redactions += sum(counts.values())
        return text[:220]

    failed = [
        {
            "title": clean(c.get("title")),
            "severity": c.get("severity"),
            "category": clean(c.get("category")),
            "can_fix": bool(c.get("can_fix")),
            "evidence": clean(c.get("evidence")),
        }
        for c in checks
        if c.get("status") == "fail"
    ][:10]
    alerts = [
        {
            "title": clean(a.get("title")),
            "severity": a.get("severity"),
            "summary": clean(a.get("summary")),
        }
        for a in (threats.get("alerts") or [])
    ][:6]
    payload = {
        "os": host.get("os"),
        "rag_level": posture.get("level"),
        "secured": posture.get("secured"),
        "securable_total": posture.get("securable_total"),
        "failed_checks": failed,
        "active_threats_count": threats.get("count", 0),
        "active_threats": alerts,
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), total_redactions


def _parse_triage_json(raw_text: str) -> dict:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        cleaned = cleaned[start:end + 1]
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object.")
    summary = str(parsed.get("summary") or "").strip()[:320]
    verdict = str(parsed.get("threat_verdict") or "").strip()[:240]
    actions = parsed.get("top_actions")
    if not isinstance(actions, list):
        actions = []
    clean_actions = [str(item).strip()[:180] for item in actions if isinstance(item, str) and item.strip()][:3]
    if not summary:
        raise ValueError("Missing summary in AI response.")
    return {"summary": summary, "threat_verdict": verdict, "top_actions": clean_actions}


def _call_cloud_api(endpoint: str, api_key: str, model: str, user_content: str) -> str:
    host, port, path = _validate_cloud_endpoint(endpoint)
    pinned_ip = _resolve_public_ip(host, port)
    context = ssl.create_default_context()
    body = json.dumps({
        "model": model,
        "temperature": 0.1,
        "max_tokens": 320,
        "messages": [
            {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Host": host if port == 443 else f"{host}:{port}",
        "User-Agent": "Wardr/0.3",
    }
    conn = _PinnedHTTPSConnection(host, port, pinned_ip=pinned_ip, timeout=_CLOUD_TIMEOUT, context=context)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise AITierError(f"Could not reach the Tier 2 cloud AI endpoint ({host}).") from exc
    finally:
        conn.close()
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AITierError("Tier 2 cloud AI returned a response exceeding Wardr's size limit.")
    if resp.status >= 400:
        raise AITierError(f"Tier 2 cloud AI returned HTTP {resp.status}. Check your API key and model name.")
    try:
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise AITierError("Tier 2 cloud AI returned an unreadable response format.") from exc
    if not isinstance(content, str) or not content.strip():
        raise AITierError("Tier 2 cloud AI returned an empty response.")
    return content


def _call_local_ollama(tag: str, user_content: str) -> str:
    payload = {
        "model": tag,
        "messages": [
            {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "format": "json",
        "stream": False,
        "keep_alive": "2m",
        "options": {"num_ctx": 4096, "num_predict": 320, "temperature": 0.1},
    }
    try:
        response = local_ai._request("/api/chat", payload, timeout=_LOCAL_TIMEOUT, limit=_MAX_RESPONSE_BYTES)
    except local_ai.LocalAIError as exc:
        raise AITierError(str(exc)) from exc
    content = (response.get("message") or {}).get("content")
    if not isinstance(content, str) or not content.strip():
        raise AITierError("Local Ollama model returned an empty response.")
    return content


def run_triage(
    state_dir: Path,
    *,
    host: dict,
    posture: dict,
    checks: list,
    threats: dict,
    offline: bool = False,
) -> dict:
    """Run redacted AI triage on the active Tier 2 (cloud) or Tier 3 (local) model."""
    cfg = load_config(state_dir)
    tier = cfg["active_tier"]
    if tier == "radar":
        raise AITierError("Enable Tier 2 (Free Cloud AI Offload) or Tier 3 (Local Heavy AI) to run AI threat triage.")
    prompt_json, redactions = _build_redacted_prompt(host, posture, checks, threats)
    if tier == "cloud":
        if offline:
            raise AITierError("Tier 2 Cloud AI is disabled while Wardr is in offline mode. Switch to Tier 3 Local AI.")
        if not cfg["cloud_api_key"]:
            raise AITierError("Add a free-tier API key in AI Protection Settings to use Tier 2 Cloud AI.")
        raw = _call_cloud_api(cfg["cloud_endpoint"], cfg["cloud_api_key"], cfg["cloud_model"], prompt_json)
        model_used = cfg["cloud_model"]
        tier_label = "Tier 2 · Cloud AI Offload"
    else:
        profile = LOCAL_PROFILES[cfg["local_profile"]]
        ollama_ok, installed = _ollama_installed_models()
        if not ollama_ok:
            raise AITierError("Start Ollama on 127.0.0.1:11434 to run Tier 3 Local AI.")
        if not _tag_installed(profile["ollama_tag"], installed):
            raise AITierError(
                f"Model {profile['label']} is not installed in Ollama yet. "
                f"Run: ollama pull {profile['ollama_tag']}"
            )
        raw = _call_local_ollama(profile["ollama_tag"], prompt_json)
        model_used = profile["label"]
        tier_label = "Tier 3 · Heavy Local AI"

    try:
        parsed = _parse_triage_json(raw)
    except ValueError as exc:
        raise AITierError("The AI model returned an unstructured reply. Wardr's deterministic checklist remains authoritative.") from exc

    return {
        "tier": tier,
        "tier_label": tier_label,
        "model": model_used,
        "redactions_applied": redactions,
        "analyzed_at": _utc_now(),
        **parsed,
    }
