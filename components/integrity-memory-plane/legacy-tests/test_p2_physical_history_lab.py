from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_physical_history_lab import run  # noqa: E402


def test_small_physical_history_is_real_rebuildable_and_retrievable(tmp_path: Path) -> None:
    args = argparse.Namespace(
        event_count=512,
        root=tmp_path / "physical",
        batch_size=128,
        bucket_span=128,
        capsule_bytes=8192,
        exact_samples=5,
        progress_every=512,
        reserve_free_bytes=0,
        preflight_bytes_per_event=1,
    )
    result = run(args)
    assert result["status"] == "PASS"
    assert result["physical_event_count"] == 512
    assert result["sparse_or_extrapolated_run"] is False
    assert result["physical_billion_event_run_completed"] is False
    assert result["peak_bucket_events"] == 128
    assert result["checks"]["physical_raw_rows_equal_target"] is True
    assert result["checks"]["event_uid_duplicate_zero"] is True
    assert result["retrieval"]["causal_event_ids"] == [317, 318, 319]
    assert result["production_authority"] is False

