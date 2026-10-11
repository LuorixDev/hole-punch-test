"""Voice-message capture. Recording is completed audio-file messaging, not a call.

The desktop client never installs an audio dependency at runtime: capture uses an
existing ALSA/PortAudio front end when one is present, and otherwise reports
``RECORDING_UNAVAILABLE`` instead of faking a recording. The recorded payload is
sent as a normal file message over whichever direct path is already open.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import wave

MAX_RECORDING_BYTES = 32 * 1024 * 1024
MAX_RECORDING_SECONDS = 60
SAMPLE_RATE = 16000


def _arecord_argv(device: str | None, seconds: int) -> list[str] | None:
    binary = shutil.which("arecord")
    if not binary:
        return None
    argv = [binary, "-q", "-t", "wav", "-f", "S16_LE", "-r", str(SAMPLE_RATE), "-c", "1"]
    if device:
        argv += ["-D", device]
    argv += ["-d", str(int(seconds))]
    return argv


def recorder_status() -> str:
    """"available" / "unsupported"; never claims a device is present."""
    if _arecord_argv(None, 1) is not None:
        return "available"
    return "unsupported"


def wav_payload(frames: bytes, sample_rate: int = SAMPLE_RATE, channels: int = 1) -> bytes:
    """Wrap raw PCM in a WAV container; used by tests and by the capture path."""
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(channels)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.writeframes(frames)
    return buffer.getvalue()


def inspect_wav(data: bytes) -> dict:
    """Validate an audio payload before offering it as a voice message."""
    with wave.open(io.BytesIO(data), "rb") as handle:
        return {
            "channels": handle.getnchannels(),
            "sampleRate": handle.getframerate(),
            "frames": handle.getnframes(),
            "seconds": round(handle.getnframes() / max(1, handle.getframerate()), 2),
        }


class Recorder:
    """One bounded capture at a time; state is explicit, never implied."""

    def __init__(self, device: str | None = None, seconds: int = MAX_RECORDING_SECONDS):
        self.device = device
        self.seconds = max(1, min(seconds, MAX_RECORDING_SECONDS))
        self.process: asyncio.subprocess.Process | None = None
        self.active = False

    async def start(self) -> None:
        if self.active:
            raise RuntimeError("RECORDING_BUSY")
        argv = _arecord_argv(self.device, self.seconds)
        if argv is None:
            raise RuntimeError("RECORDING_UNAVAILABLE")
        self.process = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        self.active = True

    async def stop(self) -> tuple[bytes, dict]:
        if not self.active or self.process is None:
            raise RuntimeError("RECORDING_FAILED")
        process = self.process
        try:
            if process.returncode is None:
                # SIGINT makes the recorder finalize the RIFF header.
                process.send_signal(2)
            stdout, _ = await asyncio.wait_for(process.communicate(), 10)
        except (asyncio.TimeoutError, ProcessLookupError):
            process.kill()
            stdout, _ = await process.communicate()
        finally:
            self.active = False
            self.process = None
        if len(stdout) > MAX_RECORDING_BYTES:
            raise RuntimeError("RECORDING_LIMIT")
        if len(stdout) <= 44:
            raise RuntimeError("RECORDING_FAILED")
        return stdout, inspect_wav(stdout)
