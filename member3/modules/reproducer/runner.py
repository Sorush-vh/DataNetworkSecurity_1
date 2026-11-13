import os
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

    if returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "UNKNOWN_SIGNAL"

    if returncode != 0:
        return f"EXIT_CODE_{returncode}"

    return None


def execute_once(command, input_data=None, timeout=5, environment=None, cwd=None):
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

        return {
            "command": command,
            "returncode": returncode,
            "signal": (
                signal.Signals(-returncode).name
                if returncode < 0
                else None
            ),
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
        (
            result["error_type"],
            result["returncode"],
            result["signal"],
            result["timed_out"]
        )
        for result in results
    ]

    stable = len(set(signatures)) == 1

    return {
        "repetitions": repetitions,
        "status": "STABLE" if stable else "FLAKY",
        "results": results
    }
