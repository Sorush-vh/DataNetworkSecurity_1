
def split_input(data, n):
    length = len(data)

    if n < 1:
        raise ValueError("n must be at least 1")

    return [
        data[i * length // n:(i + 1) * length // n]
        for i in range(n)
    ]


def delta_debug_with_report(data, test_function):
    """
    Minimize input while preserving the failure.

    test_function must return True only when the same
    error type and relevant failure location are reproduced.

    Returns minimization results and execution statistics.
    """
    test_count = 0

    def run_test(candidate):
        nonlocal test_count
        test_count += 1
        return bool(test_function(candidate))

    original_size = len(data)

    if not data:
        return {
            "status": "EMPTY_INPUT",
            "original": data,
            "minimized": data,
            "original_size": original_size,
            "minimized_size": original_size,
            "reduction_ratio": 0.0,
            "test_count": test_count,
            "validated": False
        }

    if not run_test(data):
        return {
            "status": "FAILURE_NOT_REPRODUCED",
            "original": data,
            "minimized": data,
            "original_size": original_size,
            "minimized_size": original_size,
            "reduction_ratio": 0.0,
            "test_count": test_count,
            "validated": False
        }

    current = data
    n = 2

    while len(current) >= 2:
        chunks = split_input(current, min(n, len(current)))
        reduced = False
        start = 0

        for chunk in chunks:
            end = start + len(chunk)
            complement = current[:start] + current[end:]

            if complement and run_test(complement):
                current = complement
                n = max(n - 1, 2)
                reduced = True
                break

            if chunk and run_test(chunk):
                current = chunk
                n = 2
                reduced = True
                break

            start = end

        if reduced:
            continue

        if n >= len(current):
            break

        n = min(n * 2, len(current))

    # Verify that the final minimized input still reproduces
    # the original failure.
    validated = run_test(current)

    minimized_size = len(current)

    reduction_ratio = (
        (original_size - minimized_size) / original_size
        if original_size
        else 0.0
    )

    return {
        "status": "MINIMIZED" if validated else "VALIDATION_FAILED",
        "original": data,
        "minimized": current,
        "original_size": original_size,
        "minimized_size": minimized_size,
        "reduction_ratio": reduction_ratio,
        "test_count": test_count,
        "validated": validated
    }


def delta_debug(data, test_function):
    """
    Backward-compatible interface returning only minimized input.
    """
    report = delta_debug_with_report(data, test_function)
    return report["minimized"]
