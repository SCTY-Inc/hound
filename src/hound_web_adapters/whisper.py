"""OpenAI Whisper transcription adapter (GOALIE D5).

The adapter performs exactly one provider exchange and reduces its response to
daemon-verifiable transcription provenance: the exact model the provider says
answered, the detected language, the reported duration, and ordered segments
with their timings and text.  It never retries, never selects a model on a
caller's behalf, and never returns the raw provider body.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import secrets
from typing import Any

from ._http import AdapterError, Transport, json_object, request


API_URL = "https://api.openai.com/v1/audio/transcriptions"
MODEL = "whisper-1"
RESPONSE_FORMAT = "verbose_json"
MAX_AUDIO_BYTES = 25 * 1024 * 1024
MAX_SEGMENTS = 2_048
MAX_SEGMENT_CHARS = 8_000
# Whisper reports second-resolution floats; the daemon keeps integer
# milliseconds so timings hash and compare exactly.
MILLISECONDS = 1_000


def _retrieved_at(value: str | None) -> str:
    return value or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _milliseconds(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AdapterError(f"Whisper {label} is not a number", requests=1)
    scaled = round(float(value) * MILLISECONDS)
    if scaled < 0 or scaled > 2**40:
        raise AdapterError(f"Whisper {label} is out of bounds", requests=1)
    return int(scaled)


def _multipart(audio: bytes, *, filename: str) -> tuple[str, bytes]:
    """Encode the one provider request body without a third-party client."""

    boundary = f"----hound{secrets.token_hex(16)}"
    marker = f"--{boundary}".encode("ascii")
    parts = [
        marker,
        b'Content-Disposition: form-data; name="model"',
        b"",
        MODEL.encode("ascii"),
        marker,
        b'Content-Disposition: form-data; name="response_format"',
        b"",
        RESPONSE_FORMAT.encode("ascii"),
        marker,
        f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode("ascii"),
        b"Content-Type: application/octet-stream",
        b"",
        audio,
        f"--{boundary}--".encode("ascii"),
        b"",
    ]
    return boundary, b"\r\n".join(parts)


def _segments(value: object, text: str) -> list[dict[str, Any]]:
    if value is None:
        raise AdapterError("Whisper response has no segments", requests=1)
    if not isinstance(value, list) or not value or len(value) > MAX_SEGMENTS:
        raise AdapterError("Whisper segments are invalid", requests=1)
    segments: list[dict[str, Any]] = []
    previous_end = 0
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise AdapterError("Whisper segment must be an object", requests=1)
        start = _milliseconds(item.get("start"), "segment start")
        end = _milliseconds(item.get("end"), "segment end")
        segment_text = item.get("text")
        if not isinstance(segment_text, str) or not segment_text or len(segment_text) > MAX_SEGMENT_CHARS:
            raise AdapterError("Whisper segment text is invalid", requests=1)
        if end < start or start < previous_end:
            raise AdapterError("Whisper segments are not ordered", requests=1)
        previous_end = end
        segments.append({"index": index, "start_ms": start, "end_ms": end, "text": segment_text})
    if "".join(segment["text"] for segment in segments) != text:
        raise AdapterError("Whisper segments do not reconstruct the transcript", requests=1)
    return segments


def transcribe(
    transcribe_input: Mapping[str, Any],
    *,
    env: Mapping[str, str],
    transport: Transport = request,
    retrieved_at: str | None = None,
    timeout: float = 120,
) -> dict[str, Any]:
    """Run one Whisper exchange over already-authorized capture bytes."""

    if not isinstance(transcribe_input, Mapping):
        raise AdapterError("transcribe input must be a mapping")
    audio = transcribe_input.get("audio")
    capture_id = transcribe_input.get("capture_id")
    if type(audio) is not bytes or not audio or len(audio) > MAX_AUDIO_BYTES:
        raise AdapterError("capture bytes are outside the transcribable representation")
    if not isinstance(capture_id, str) or len(capture_id) != 64:
        raise AdapterError("capture identity is invalid")
    api_key = env.get("OPENAI_API_KEY")
    if not isinstance(api_key, str) or not api_key or any(ord(character) < 33 for character in api_key):
        raise AdapterError("OPENAI_API_KEY is required")

    boundary, body = _multipart(audio, filename=f"{capture_id}.bin")
    try:
        status, provider_raw = transport(
            method="POST",
            url=API_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "hound-whisper/0.1",
            },
            body=body,
            timeout=timeout,
        )
    except AdapterError as error:
        raise AdapterError(str(error), raw=error.raw, media_type=error.media_type, requests=1) from error
    try:
        response = json_object(status, provider_raw, "Whisper")
    except AdapterError as error:
        raise AdapterError(str(error), raw=error.raw, media_type=error.media_type, requests=1) from error

    text = response.get("text")
    if not isinstance(text, str):
        raise AdapterError("Whisper response has no transcript", requests=1)
    language = response.get("language")
    if language is not None and (not isinstance(language, str) or not language or len(language) > 64):
        raise AdapterError("Whisper language is invalid", requests=1)
    duration = _milliseconds(response.get("duration"), "duration") if "duration" in response else None
    # The provider names the exact model that answered; the daemon never
    # substitutes its requested model for the reported one.
    model = response.get("model")
    if model is not None and (not isinstance(model, str) or not model or len(model) > 128):
        raise AdapterError("Whisper model identity is invalid", requests=1)
    segments = _segments(response.get("segments"), text) if text else []
    return {
        "retrieved_at": _retrieved_at(retrieved_at),
        "output": {
            "capture_id": capture_id,
            "text": text,
            "language": language or "none",
            "model": MODEL,
            "model_version": model or MODEL,
            "duration_ms": duration,
            "segments": segments,
        },
        "usage": {"requests": 1, "bytes": len(provider_raw)},
    }


__all__ = ["API_URL", "MAX_AUDIO_BYTES", "MAX_SEGMENTS", "MODEL", "transcribe"]
