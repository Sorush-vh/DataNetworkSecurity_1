
import os
import re
import signal
import subprocess


def detect_error_type(stderr, returncode, timed_out):
    if timed_out:
        return "TIMEOUT"

    error_output = stderr.lower()

    if "stack smashing detected" in error_output:
        return "STACK_SMASHING"

    if "addresssanitizer" in error_output:
        return "ADDRESS_SANITIZER"

    if "segmentation fault" in error_output:
        return "SEGMENTATION_FAULT"

    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "UNKNOWN_SIGNAL"

    if returncode is not None and returncode != 0:
        return f"EXIT_CODE_{returncode}"

    return None


def normalize_diagnostic(stderr):
    """
    Normalize volatile values such as memory addresses and process IDs
    before comparing diagnostics from repeated executions.
    """
    normalized = stderr.lower()

    normalized = re.sub(
        r"0x[0-9a-f]+",
        "<address>",
        normalized
    )

    normalized = re.sub(
        r"\bpid[=: ]+\d+\b",
        "pid=<number>",
        normalized
    )

    return normalized.strip()


def execute_once(command, input_data=None, timeout=5,
                 environment=None, cwd=None):

    env = os.environ.copy()

    if environment:
        env.update(environment)

    try:
        result = subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
            shell=False
        )

        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")

        returncode = result.returncode

        try:
            process_signal = (
                signal.Signals(-returncode).name
                if returncode < 0
                else None
            )
        except ValueError:
            process_signal = "UNKNOWN_SIGNAL"

        return {
            "command": command,
            "returncode": returncode,
            "signal": process_signal,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": False,
            "error_type": detect_error_type(
                stderr, returncode, False
            )
        }

    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "error_type": "TIMEOUT"
        }

    except OSError as error:
        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "stdout": "",
            "stderr": str(error),
            "timed_out": False,
            "error_type": "EXECUTION_ERROR"
        }



def _result_signature(result):
    """
    Build a signature from the execution outcome and normalized
    standard output and diagnostic output.
    """
    return (
        result["error_type"],
        result["returncode"],
        result["signal"],
        result["timed_out"],
        normalize_diagnostic(result["stdout"]),
        normalize_diagnostic(result["stderr"])
    )


def replay(command, repetitions=3, input_data=None,
           timeout=5, environment=None, cwd=None):

    if repetitions < 3:
        raise ValueError("At least 3 replays are required")

    results = []

    for _ in range(repetitions):
        result = execute_once(
            command=command,
            input_data=input_data,
            timeout=timeout,
            environment=environment,
            cwd=cwd
        )

        results.append(result)

    signatures = [
        _result_signature(result)
        for result in results
    ]

    stable = len(set(signatures)) == 1

    return {
        "repetitions": repetitions,
        "status": "STABLE" if stable else "FLAKY",
        "results": results
    }
