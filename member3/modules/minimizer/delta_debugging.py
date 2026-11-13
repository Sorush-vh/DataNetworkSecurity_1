
def split_input(data, n):
    length = len(data)

    return [
        data[i * length // n:(i + 1) * length // n]
        for i in range(n)
    ]


def delta_debug(data, test_function):
    """
    Minimize input while preserving the same failure.

    test_function must return True only if the same
    error type and relevant failure location are reproduced.
    """
    if not data or not test_function(data):
        return data

    current = data
    n = 2

    while len(current) >= 2:
        chunks = split_input(current, min(n, len(current)))
        reduced = False
        start = 0

        for chunk in chunks:
            end = start + len(chunk)

            complement = current[:start] + current[end:]

            if complement and test_function(complement):
                current = complement
                n = max(n - 1, 2)
                reduced = True
                break

            if chunk and test_function(chunk):
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

    return current
