# SPDX-License-Identifier: AGPL-3.0-only
"""Check optimized entropy against a direct Shannon calculation."""

import math
import random

import pytest

from backends.static.binary.entropy import entropy_of_bytes, high_entropy_regions


def reference_entropy(data):
    if not data:
        return 0.0
    probabilities = [data.count(value) / len(data) for value in range(256)]
    return -sum(p * math.log2(p) for p in probabilities if p)


@pytest.mark.parametrize("length", [0, 1, 2, 17, 255, 256, 1024, 4096, 4097, 8192])
def test_entropy_matches_reference_for_window_and_file_sizes(length):
    rng = random.Random(length)
    for data in (rng.randbytes(length), b"A" * length, (b"abc" * length)[:length]):
        assert entropy_of_bytes(data) == pytest.approx(
            reference_entropy(data), rel=0, abs=1e-12
        )


@pytest.mark.parametrize("window,step", [(64, 16), (256, 64), (257, 31), (256, 300)])
def test_region_boundaries_and_maxima_match_reference(tmp_path, window, step):
    data = b"\x00" * 512 + random.Random(42).randbytes(2048) + b"\xff" * 512
    path = tmp_path / "regions.bin"
    path.write_bytes(data)
    expected = []
    active = None
    for offset in range(0, len(data) - window + 1, step):
        entropy = reference_entropy(data[offset : offset + window])
        if entropy >= 5.0:
            if active is None:
                active = {
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "entropy": entropy,
                }
                expected.append(active)
            else:
                active["entropy"] = max(active["entropy"], entropy)
        else:
            active = None
    for region in expected:
        region["entropy"] = round(region["entropy"], 4)
    assert (
        high_entropy_regions(str(path), threshold=5.0, window=window, step=step)
        == expected
    )
