"""Explicit host-side media sinks. No automatic downloads, installation or logging.

Calls require admission by the hosting adapter, which also owns OS containment.
Importing this module performs no I/O. Model libraries are loaded lazily.
"""
from __future__ import annotations

import io
import os
import re
import stat
import subprocess
import tempfile
import warnings
import wave
from pathlib import Path
from typing import Any

from . import contracts as c

MAX_MEDIA = 8 * 1024 * 1024


def verified_file(filename: Path, expected: str, maximum: int = MAX_MEDIA) -> bytes:
    """Read one regular, non-linked file into an immutable verified byte snapshot."""
    c.digest(expected)
    c.integer(maximum, 1, 1024**3, "invalid_file_limit")
    filename = Path(os.path.abspath(filename))
    for part in (filename, *filename.parents):
        c.require(not part.is_symlink(), "symlink_rejected")
    fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        c.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                  "regular_unlinked_file_required")
        c.require(before.st_size <= maximum, "file_limit")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    c.require(len(data) <= maximum and (before.st_size, before.st_mtime_ns, before.st_ino)
              == (after.st_size, after.st_mtime_ns, after.st_ino), "file_changed_or_oversized")
    c.require(c.sha(data) == expected, "file_digest_mismatch")
    return data


def pcm_wave(data: bytes, *, rate: int | None = None) -> tuple[bytes, int, int]:
    c.require(type(data) is bytes and 44 <= len(data) <= MAX_MEDIA, "audio_size_limit")
    try:
        with wave.open(io.BytesIO(data), "rb") as audio:
            actual_rate, frames = audio.getframerate(), audio.getnframes()
            c.require(audio.getnchannels() == 1 and audio.getsampwidth() == 2
                      and audio.getcomptype() == "NONE", "pcm16_mono_required")
            c.require(8000 <= actual_rate <= 48000 and (rate is None or rate == actual_rate),
                      "unsupported_sample_rate")
            c.require(0 < frames <= actual_rate * 120, "audio_duration_limit")
            raw = audio.readframes(frames + 1)
            c.require(len(raw) == frames * 2, "truncated_or_inconsistent_pcm")
    except (wave.Error, EOFError) as exc:
        raise c.ContractError("invalid_wave") from exc
    return raw, actual_rate, max(1, (frames * 1000 + actual_rate - 1) // actual_rate)


class LocalWhisper:
    """faster-whisper backend using only a verified, complete in-memory model bundle.

    The host MUST bound CPU/GPU time and memory in an admitted worker. Input is
    already decoded PCM; arbitrary ffmpeg/PyAV media decoding is not used.
    """

    def __init__(self, root: Path, files: dict[str, str], identity: dict[str, Any],
                 *, device: str = "cpu", compute_type: str = "int8") -> None:
        c.model_identity(identity)
        c.require(type(files) is dict and 4 <= len(files) <= 32, "model_manifest_limit")
        required = {"model.bin", "config.json", "tokenizer.json", "preprocessor_config.json",
                    "LICENSE"}
        c.require(required <= set(files), "complete_offline_bundle_required")
        root = Path(root)
        c.require(root.is_dir() and not root.is_symlink(), "local_model_directory_required")
        c.require(device in ("cpu", "cuda") and compute_type in ("int8", "float16", "float32"),
                  "unsupported_compute_configuration")
        bundle: dict[str, bytes] = {}
        total = 0
        for name, expected in sorted(files.items()):
            c.path(name)
            raw = verified_file(root / name, expected, 512 * 1024 * 1024)
            total += len(raw)
            c.require(total <= 768 * 1024 * 1024, "model_bundle_size_limit")
            bundle[name] = raw
        c.require(c.sha(bundle["model.bin"]) == identity["weights_sha256"]
                  and c.sha(bundle["LICENSE"]) == identity["license_sha256"],
                  "model_identity_mismatch")
        c.require(bundle["tokenizer.json"] and bundle["preprocessor_config.json"],
                  "offline_tokenizer_required")
        c.load_json(bundle["config.json"])
        c.load_json(bundle["preprocessor_config.json"])
        try:
            from faster_whisper import WhisperModel
        except ImportError as exc:
            raise c.ContractError("faster_whisper_not_installed") from exc
        self.identity = c.load_json(c.canonical(identity))
        bundle.pop("LICENSE")
        self._model = WhisperModel("integrity-verified-bundle", files=bundle,
                                  local_files_only=True, device=device,
                                  compute_type=compute_type, cpu_threads=2, num_workers=1)

    def transcribe(self, data: bytes, language: str) -> dict[str, Any]:
        c.require(type(language) is str and bool(re.fullmatch(r"[a-z]{2,3}", language)),
                  "explicit_language_required")
        raw, _, duration = pcm_wave(data, rate=16000)
        try:
            import numpy as np
        except ImportError as exc:
            raise c.ContractError("numpy_not_installed") from exc
        samples = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
        segments, _ = self._model.transcribe(samples, language=language, beam_size=1,
                                             vad_filter=False, condition_on_previous_text=False)
        output, last_start, characters = [], -1, 0
        for item in segments:
            c.require(len(output) < 4096, "transcript_segment_limit")
            start, end = round(item.start * 1000), round(item.end * 1000)
            c.integer(start, 0, duration, "invalid_segment_start")
            c.integer(end, start + 1, duration, "invalid_segment_end")
            c.require(start >= last_start, "unordered_segments")
            last_start = start
            phrase = item.text.strip()
            if not phrase:
                continue
            c.text(phrase, 8192)
            characters += len(phrase)
            c.require(characters <= 32768, "transcript_text_limit")
            output.append({"start_ms": start, "end_ms": end, "text": phrase, "speaker": None})
        return c.candidate("transcript", {
            "report": {"audio_sha256": c.sha(data), "duration_ms": duration, "language": language,
                       "model": self.identity, "segments": output},
            "source_bytes_verified": True, "model_bytes_verified": True,
            "epistemic_state": "model_generated_unverified", "text_is_instruction": False,
            "append_performed": False, "speaker_diarization_performed": False,
        })


def synthesize_espeak(phrase: str, executable: Path, executable_sha256: str,
                      *, language: str = "en") -> tuple[bytes, dict[str, Any]]:
    """Local stock-voice fallback; never record audio or execute text as argv.

    The exact executable and its OS libraries/voice data are the host's admitted
    runtime. The byte precheck alone is NOT a claim of OS executable custody.
    """
    c.text(phrase, 1200)
    c.require(type(language) is str
              and bool(re.fullmatch(r"[a-z]{2,3}(?:-[a-z]{2})?", language)), "invalid_voice")
    executable = Path(os.path.abspath(executable))
    verified_file(executable, executable_sha256, 16 * 1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="integrity-tts-") as directory:
        target = Path(directory) / "speech.wav"
        environment = {"PATH": os.defpath, "LANG": "C.UTF-8"}
        if os.name == "nt":
            environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
        try:
            subprocess.run([str(executable), "--stdin", "-v", language, "-s", "170",
                            "-w", str(target)], input=phrase.encode("utf-8"),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           cwd=directory, env=environment, timeout=20, check=True, shell=False)
        except (subprocess.SubprocessError, OSError) as exc:
            raise c.ContractError("tts_execution_failed_no_retry") from exc
        c.require(target.is_file() and not target.is_symlink()
                  and target.stat().st_size <= MAX_MEDIA, "tts_output_limit")
        with target.open("rb") as stream:
            data = stream.read(MAX_MEDIA + 1)
        _, sample_rate, duration = pcm_wave(data)
    return data, c.candidate("synthesis", {
        "text_sha256": c.sha(phrase.encode("utf-8")), "audio_sha256": c.sha(data),
        "language": language, "sample_rate": sample_rate, "duration_ms": duration,
        "backend": "espeak-local", "backend_sha256": executable_sha256,
        "voice_kind": "stock", "cloud_used": False, "playback_performed": False,
        "executable_custody_verified": False, "independent_outcome_verified": False,
    })


def decoded_companion(manifest: dict[str, Any], data: bytes) -> tuple[bytes, dict[str, Any]]:
    """Verify, fully decode, check true dimensions, then strip image metadata."""
    c.validate_companion(manifest, data)
    try:
        from PIL import Image
    except ImportError as exc:
        raise c.ContractError("pillow_not_installed") from exc
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data), formats=("PNG", "WEBP")) as image:
                c.require(image.size == (manifest["width"], manifest["height"]),
                          "image_dimensions_mismatch")
                c.require(image.width * image.height <= 4_194_304 and
                          getattr(image, "n_frames", 1) == 1, "decoded_image_limit")
                image.verify()
            with Image.open(io.BytesIO(data), formats=("PNG", "WEBP")) as image:
                image.load()
                safe = Image.new("RGBA", image.size)
                safe.paste(image.convert("RGBA"))
                output = io.BytesIO()
                safe.save(output, format="PNG")
                normalized = output.getvalue()
                c.require(len(normalized) <= MAX_MEDIA, "normalized_image_limit")
    except c.ContractError:
        raise
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombWarning,
            Image.DecompressionBombError) as exc:
        raise c.ContractError("image_decode_rejected") from exc
    return normalized, c.candidate("companion-decoded", {
        "source_sha256": c.sha(data), "normalized_sha256": c.sha(normalized),
        "width": manifest["width"], "height": manifest["height"],
        "image_decode_verified": True, "dimensions_verified": True,
        "metadata_retained": False, "installation_performed": False,
    })
