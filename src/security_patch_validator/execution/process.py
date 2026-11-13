"""Execute a local Linux process and capture bounded, independent streams."""

from __future__ import annotations

import base64
import os
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _wait_for_exit(pid: int, deadline: float) -> bool:
    # Leave the leader waitable until its process group has been cleaned up.
    while not os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, 0.01))
    return True


def _signal_name(number: int | None) -> str | None:
    if number is None:
        return None
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"SIG{number}"


def _log_fields(name: str, data: bytes, truncated: bool) -> dict[str, Any]:
    fields = {name: data.decode("utf-8", errors="replace"), f"{name}_truncated": truncated}
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        fields[f"{name}_base64"] = base64.b64encode(data).decode("ascii")
    return fields


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    max_output_bytes: int,
    stdin: bytes | None = None,
) -> dict[str, Any]:
    """Preserve the actual wait status and report runner-enforced stops separately."""
    started = time.monotonic()
    deadline = started + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = dict.fromkeys(buffers, False)
    stop_reason = launch_error = returncode = None
    with tempfile.TemporaryFile() as input_stream:
        if stdin is not None:
            input_stream.write(stdin)
            input_stream.seek(0)
        try:
            process = subprocess.Popen(
                argv, cwd=cwd, env=env,
                stdin=input_stream if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
        except OSError as exc:
            launch_error = f"{type(exc).__name__}: {exc}"
        else:
            assert process.stdout is not None and process.stderr is not None
            with process.stdout, process.stderr, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                try:
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            stop_reason = "timeout"
                            break
                        for key, _ in selector.select(remaining):
                            data = os.read(key.fd, 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            name = key.data
                            room = max_output_bytes - len(buffers[name])
                            buffers[name].extend(data[:room])
                            if len(data) > room:
                                truncated[name] = True
                                stop_reason = "output-limit"
                        if stop_reason is not None:
                            break
                    if stop_reason is None and not _wait_for_exit(process.pid, deadline):
                        stop_reason = "timeout"
                finally:
                    # The leader can exit while descendants still own its pipes.
                    _kill_group(process)
                    if stop_reason is not None:
                        for key in selector.get_map().values():
                            truncated[key.data] = True
                    returncode = process.wait()

    signal_number = -returncode if returncode is not None and returncode < 0 else None
    signal_name = _signal_name(signal_number)
    resource_limit = {"SIGXCPU": "cpu", "SIGXFSZ": "file-size"}.get(signal_name)
    if stop_reason == "output-limit":
        resource_limit = "output"
    return {
        "exit_code": returncode if returncode is not None and returncode >= 0 else None,
        "signal": signal_name,
        "signal_number": signal_number,
        "timeout": stop_reason == "timeout",
        "resource_limit": resource_limit,
        "runner_stop": stop_reason,
        "launch_error": launch_error,
        "duration_seconds": round(time.monotonic() - started, 6),
        "logs_truncated": any(truncated.values()),
        **_log_fields("stdout", bytes(buffers["stdout"]), truncated["stdout"]),
        **_log_fields("stderr", bytes(buffers["stderr"]), truncated["stderr"]),
    }
