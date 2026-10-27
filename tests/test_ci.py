# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Keep the GitHub Actions workflows parseable.

An unquoted colon inside a step name (``- name: mypy (gradual: web layer)``) makes the whole file invalid YAML.
GitHub then runs nothing at all: the run appears in the Actions tab under the file path with zero jobs, which is
easy to miss until someone reads the annotation. Parsing every workflow here catches the same class of error in
a normal ``pytest`` run, before the push.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))
IDS = [p.name for p in FILES]


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_workflow_parses(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name}: a workflow must be a mapping"
    assert doc.get("jobs"), f"{path.name}: no jobs defined"


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_every_step_is_runnable(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for name, job in doc["jobs"].items():
        assert "runs-on" in job, f"{path.name}: job {name!r} has no runs-on"
        steps = job.get("steps") or []
        assert steps, f"{path.name}: job {name!r} has no steps"
        for i, step in enumerate(steps, 1):
            assert ("uses" in step) != ("run" in step), \
                f"{path.name}: job {name!r} step {i} needs exactly one of uses/run"
