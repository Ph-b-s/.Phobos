"""Hardware-aware setup for Phobos's local Mistral security brain."""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from ai import MODEL_NAME, AIError, _http_json, _validate_local_url

SETUP_DIR = Path.home() / ".phobos"
SETUP_FILE = SETUP_DIR / "ai_setup.json"

Q4_MODEL = "mistral-small3.2:24b-instruct-2506-q4_K_M"
Q8_MODEL = "mistral-small3.2:24b-instruct-2506-q8_0"
FP16_MODEL = "mistral-small3.2:24b-instruct-2506-fp16"
FALLBACK_MODEL = "mistral:7b-instruct"


@dataclass(frozen=True, slots=True)
class HardwareProfile:
    system_ram_gb: float
    gpu_vram_gb: float
    gpu_vendor: str
    cpu_count: int
    architecture: str
    platform: str


@dataclass(frozen=True, slots=True)
class ModelProfile:
    name: str
    size_gb: float
    tier: str
    reason: str


def _ram_gb() -> float:
    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_phys", ctypes.c_ulonglong),
                    ("avail_phys", ctypes.c_ulonglong),
                    ("total_page", ctypes.c_ulonglong),
                    ("avail_page", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("avail_virtual", ctypes.c_ulonglong),
                    ("avail_extended", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.total_phys / (1024**3)
        except (AttributeError, OSError, ValueError):
            pass
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return pages * page_size / (1024**3)
    except (AttributeError, OSError, ValueError):
        return 16.0


def _nvidia_vram_gb() -> float:
    binary = shutil.which("nvidia-smi")
    if not binary:
        return 0.0
    try:
        result = subprocess.run(
            [binary, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
        values = []
        for line in result.stdout.splitlines():
            try:
                values.append(float(line.strip()) / 1024.0)
            except ValueError:
                continue
        return max(values, default=0.0)
    except (OSError, subprocess.SubprocessError):
        return 0.0


def detect_hardware() -> HardwareProfile:
    vram = _nvidia_vram_gb()
    vendor = "NVIDIA" if vram else "Unknown"
    return HardwareProfile(
        system_ram_gb=round(_ram_gb(), 1),
        gpu_vram_gb=round(vram, 1),
        gpu_vendor=vendor,
        cpu_count=os.cpu_count() or 1,
        architecture=platform.machine(),
        platform=platform.platform(aliased=True),
    )


def select_model(profile: HardwareProfile) -> ModelProfile:
    """Choose the strongest Mistral profile that should fit conservatively.

    The size thresholds include headroom for runtime + context, not merely the
    raw model-file size. Mistral Small 3.2 Q4 is about 15 GB, Q8 about 26 GB,
    and FP16 about 48 GB in the current Ollama catalogue.
    """
    memory = max(profile.system_ram_gb, profile.gpu_vram_gb)

    if profile.gpu_vram_gb >= 48 and profile.system_ram_gb >= 64:
        return ModelProfile(FP16_MODEL, 48.0, "maximum", "High-memory workstation can use the full-precision 24B model")
    if profile.gpu_vram_gb >= 28 and profile.system_ram_gb >= 40:
        return ModelProfile(Q8_MODEL, 26.0, "high", "Enough GPU/system memory for the higher-quality 24B quantization")
    if memory >= 18 and profile.system_ram_gb >= 24:
        return ModelProfile(Q4_MODEL, 15.0, "balanced", "Best balance of reasoning quality and broad desktop compatibility")
    if profile.system_ram_gb >= 12:
        return ModelProfile(FALLBACK_MODEL, 4.4, "compact", "24B Mistral Small would be too memory-constrained; using Mistral 7B keeps Phobos usable")
    return ModelProfile(FALLBACK_MODEL, 4.4, "minimum", "System memory is limited; using the smallest supported Mistral runtime")


def _read_state() -> dict:
    try:
        return json.loads(SETUP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(profile: HardwareProfile, model: ModelProfile, *, completed: bool) -> None:
    SETUP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "completed": completed,
        "hardware": asdict(profile),
        "model": asdict(model),
    }
    SETUP_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def setup_status(base_url: str) -> dict[str, object]:
    _validate_local_url(base_url)
    profile = detect_hardware()
    model = select_model(profile)
    state = _read_state()
    installed = False
    runtime_running = False
    try:
        _http_json(base_url.rsplit("/api/", 1)[0] + "/api/version", timeout=2.0, max_bytes=16_384)
        runtime_running = True
        tags = _http_json(base_url.rsplit("/api/", 1)[0] + "/api/tags", timeout=3.0)
        installed = model.name in {
            item.get("name") for item in tags.get("models", []) if isinstance(item, dict)
        }
    except AIError:
        pass
    return {
        "first_run": not bool(state.get("completed")),
        "runtime_running": runtime_running,
        "model_installed": installed,
        "selected_model": asdict(model),
        "hardware": asdict(profile),
    }


def prepare_model(client, profile: HardwareProfile | None = None) -> ModelProfile:
    profile = profile or detect_hardware()
    model = select_model(profile)
    client.config = client.config.__class__(
        base_url=client.config.base_url,
        model=model.name,
        timeout=client.config.timeout,
        auto_start_runtime=client.config.auto_start_runtime,
        auto_pull_model=client.config.auto_pull_model,
    )
    client._ensure_runtime()
    client._ensure_model()
    _write_state(profile, model, completed=True)
    return model
