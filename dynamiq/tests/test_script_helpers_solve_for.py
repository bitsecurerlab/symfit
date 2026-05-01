from __future__ import annotations

from typing import Any

from dynamiq.script_helpers import BytesReplayAdapter, apply_byte_assignments, solve_for


class FakeSession:
    def __init__(self, models: dict[str, dict[str, Any]]):
        self.models = models
        self.solved_labels: list[tuple[str, bool]] = []

    def recent_path_constraints(self, limit: int = 16) -> dict[str, Any]:
        return {
            "ok": True,
            "result": {
                "constraints": [
                    {"label": "0x1", "taken": True},
                    {"label": "0x1", "taken": True},
                    {"label": "0x2", "taken": True},
                ][:limit],
                "count": 3,
            },
        }

    def solve_path_constraint(self, label: str, negate: bool = True) -> dict[str, Any]:
        self.solved_labels.append((label, negate))
        return {"ok": True, "result": self.models[label]}


def test_apply_byte_assignments_patches_and_extends_seed():
    candidate = apply_byte_assignments(
        b"ABC",
        [
            {"offset": "0x1", "value": 0x78},
            {"offset": 4, "value_hex": "0x7a"},
        ],
    )

    assert candidate == b"AxC\x00z"


def test_apply_byte_assignments_rejects_invalid_values():
    invalid_cases = [
        [{"offset": -1, "value": 0}],
        [{"offset": 0, "value": 0x100}],
        [{"offset": True, "value": 0}],
        [{"offset": 0, "value": False}],
    ]

    for assignments in invalid_cases:
        try:
            apply_byte_assignments(b"ABC", assignments)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {assignments!r}")


def test_solve_for_replays_until_verified_target_reached():
    session = FakeSession(
        {
            "0x1": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
            "0x2": {
                "status": "sat",
                "assignments": [{"offset": "0x0", "value": ord("Z")}],
                "soundness": "sound",
            },
        }
    )
    seen_candidates: list[bytes] = []

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        seen_candidates.append(candidate)
        return {"reached": candidate == b"ZBC", "target_pc": target_pc, "timeout": timeout}

    result = solve_for(
        session, "0x401234", BytesReplayAdapter(b"ABC", runner), limit=3, timeout=2.5
    )

    assert result["status"] == "reached"
    assert result["candidate"] == b"ZBC"
    assert result["candidate_hex"] == "5a4243"
    assert result["verdict"]["target_pc"] == "0x401234"
    assert seen_candidates == [b"ZBC"]
    assert session.solved_labels == [("0x1", True), ("0x2", True)]


def test_solve_for_returns_not_found_after_failed_replay():
    session = FakeSession(
        {
            "0x1": {
                "status": "sat",
                "assignments": [{"offset": "0x0", "value": ord("Z")}],
                "soundness": "sound",
            },
            "0x2": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
        }
    )

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        return {"reached": False, "candidate_len": len(candidate)}

    result = solve_for(session, "0x401234", BytesReplayAdapter(b"ABC", runner))

    assert result["status"] == "not_found"
    replay_attempts = [attempt for attempt in result["attempts"] if "verdict" in attempt]
    assert replay_attempts[0]["candidate"] == b"ZBC"
    assert replay_attempts[0]["verdict"] == {"reached": False, "candidate_len": 3}


def test_solve_for_replays_models_with_solver_assumptions():
    session = FakeSession(
        {
            "0x1": {
                "status": "sat",
                "assignments": [{"offset": 0, "value": ord("Z")}],
                "soundness": "conditional",
                "assumptions": [{"kind": "concretized_symbolic_load"}],
            },
            "0x2": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
        }
    )

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        return {"reached": candidate == b"ZBC"}

    result = solve_for(session, "0x401234", BytesReplayAdapter(b"ABC", runner))

    assert result["status"] == "reached"
    assert result["model"]["soundness"] == "conditional"
    assert result["model"]["assumptions"] == [{"kind": "concretized_symbolic_load"}]


def test_solve_for_rejects_conditional_model_when_replay_misses_target():
    session = FakeSession(
        {
            "0x1": {
                "status": "sat",
                "assignments": [{"offset": 0, "value": ord("Z")}],
                "soundness": "conditional",
            },
            "0x2": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
        }
    )

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        return {"reached": False, "reason": "verification_missed"}

    result = solve_for(
        session,
        "0x401234",
        BytesReplayAdapter(b"ABC", runner),
    )

    assert result["status"] == "not_found"
    replay_attempts = [attempt for attempt in result["attempts"] if "verdict" in attempt]
    assert replay_attempts[0]["model"]["soundness"] == "conditional"
    assert replay_attempts[0]["verdict"] == {"reached": False, "reason": "verification_missed"}


def test_solve_for_explores_candidates_returned_by_replay_verdict():
    session = FakeSession(
        {
            "0x1": {
                "status": "sat",
                "assignments": [{"offset": 0, "value": ord("B")}],
                "soundness": "sound",
            },
            "0x2": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
        }
    )
    seen_candidates: list[bytes] = []

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        seen_candidates.append(candidate)
        if candidate == b"BBC":
            return {
                "reached": False,
                "candidates": [
                    {
                        "constraint": {"label": "0x99", "taken": True},
                        "assignments": [{"offset": 1, "value": ord("Z")}],
                    }
                ],
            }
        return {"reached": candidate == b"BZC"}

    result = solve_for(session, "0x401234", BytesReplayAdapter(b"ABC", runner))

    assert result["status"] == "reached"
    assert result["candidate"] == b"BZC"
    replay_attempts = [attempt for attempt in result["attempts"] if "verdict" in attempt]
    assert replay_attempts[0]["depth"] == 0
    assert replay_attempts[1]["depth"] == 1
    assert seen_candidates == [b"BBC", b"BZC"]


def test_solve_for_respects_max_replays_for_deeper_exploration():
    session = FakeSession(
        {
            "0x1": {
                "status": "sat",
                "assignments": [{"offset": 0, "value": ord("B")}],
                "soundness": "sound",
            },
            "0x2": {
                "status": "unsat",
                "assignments": [],
                "soundness": "sound",
            },
        }
    )

    def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
        return {
            "reached": False,
            "candidates": [{"assignments": [{"offset": 1, "value": ord("Z")}]}],
        }

    result = solve_for(
        session,
        "0x401234",
        BytesReplayAdapter(b"ABC", runner),
        max_replays=1,
    )

    assert result["status"] == "not_found"
    assert result["exhausted"] is True
    assert len([attempt for attempt in result["attempts"] if "verdict" in attempt]) == 1
