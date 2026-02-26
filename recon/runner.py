"""Runner — loads a catalog, fires multi-turn scenarios, collects scored results."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from .target import Target
from .scorer import Scorer


def load_catalog(path: str | Path) -> dict:
    with open(path) as f:
        return json.load(f)


def run_catalog(
    catalog: dict,
    target: Target,
    scorer: Scorer,
    *,
    ids: list[str] | None = None,
    pass_filter: str | None = None,
    verbose: bool = True,
) -> dict:
    """Run scenarios from a catalog. Optionally filter by IDs or pass (A/B/C)."""

    attacks = catalog["attacks"]

    if ids:
        attacks = [a for a in attacks if a["id"] in ids]
    if pass_filter:
        attacks = [a for a in attacks if a.get("pass") == pass_filter]

    if not attacks:
        raise SystemExit("No scenarios matched the filter.")

    run_id = uuid.uuid4().hex[:8]
    results: dict = {
        "catalog_id": catalog["catalog_id"],
        "run_id": run_id,
        "total_scenarios": len(attacks),
        "summary": {"SUCCESS": 0, "LEAK": 0, "ECHO": 0, "BLOCKED": 0, "SAFE": 0, "ERROR": 0},
        "scenarios": [],
    }

    for i, attack in enumerate(attacks, 1):
        if verbose:
            print(f"\n[{i}/{len(attacks)}] {attack['id']}  ({attack.get('attack_family', '')})")

        session_id = uuid.uuid4().hex
        turn_results = []

        for t, prompt in enumerate(attack["turns"], 1):
            if verbose:
                label = prompt[:72] + "..." if len(prompt) > 72 else prompt
                print(f"  T{t}: {label}")

            resp = target.send(prompt, session_id)
            ts = scorer.score(resp, prompt=prompt)

            turn_results.append({
                "turn": t,
                "prompt": prompt,
                "response": resp.text[:2000],
                "elapsed_ms": round(ts.elapsed_ms, 1),
                "score": ts.score,
                "reasoning": ts.reasoning,
            })

            if verbose:
                print(f"      → {ts.score}  {ts.elapsed_ms:.0f}ms  {ts.reasoning}")

        overall = _overall(turn_results)
        results["summary"][overall] += 1

        results["scenarios"].append({
            "id": attack["id"],
            "pass": attack.get("pass"),
            "recon_target": attack.get("recon_target"),
            "signal_type": attack.get("signal_type"),
            "overall": overall,
            "turns": turn_results,
        })

    if verbose:
        print(f"\n{'='*60}")
        print(f"Run {run_id} complete — {len(attacks)} scenarios")
        for k, v in results["summary"].items():
            if v:
                print(f"  {k}: {v}")

    return results


def _overall(turns: list[dict]) -> str:
    """Roll up per-turn scores to a single scenario verdict.

    Priority: SUCCESS > LEAK > ECHO > BLOCKED > SAFE > ERROR
    Any single SUCCESS turn wins. LEAK beats ECHO beats BLOCKED.
    """
    scores = {t["score"] for t in turns}
    if "SUCCESS" in scores:
        return "SUCCESS"
    if "LEAK" in scores:
        return "LEAK"
    if "ECHO" in scores:
        return "ECHO"
    if "BLOCKED" in scores:
        return "BLOCKED"
    if "SAFE" in scores:
        return "SAFE"
    return "ERROR"
