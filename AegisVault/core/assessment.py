"""Single orchestration path for AegisVault assessments."""
import time
from fastapi import APIRouter
from .models import AssessmentRequest
from .hash_inspector import parse_record
from .dictionary_engine import generate_candidates
from .verification import verify_candidates
from .strength_analyzer import analyze_password
from .report import build_report

router = APIRouter(prefix="/api", tags=["Assessment"])

@router.post("/assessment")
def create_assessment(request: AssessmentRequest):
    started = time.perf_counter()
    candidates = generate_candidates(
        seed_words=[],
        supplied=request.candidate_words,
        include_common=request.include_common_candidates,
    )
    findings = []
    for index, line in enumerate(request.records, start=1):
        parsed = parse_record(line, index)
        if parsed is None:
            continue
        if parsed["status"] == "locked":
            parsed["hash_info"] = {"algorithm": "Locked account", "risk": "unknown",
                                   "note": "No usable password hash is present."}
            parsed["verification"] = {"status": "not_testable", "match": None, "attempts": 0}
            parsed["password_quality"] = None
        else:
            info = parsed["hash_info"]
            verification_input = dict(info)
            verification_input["digest"] = parsed["hash"]
            parsed["verification"] = verify_candidates(verification_input, candidates)
            parsed["password_quality"] = (
                analyze_password(parsed["verification"]["match"])
                if parsed["verification"]["match"] is not None else None
            )
        # Never return the supplied digest in the assessment response.
        parsed.pop("hash", None)
        findings.append(parsed)
    elapsed = time.perf_counter() - started
    report_text = build_report(findings, len(candidates), elapsed)
    return {
        "status": "completed",
        "summary": {
            "records": len(findings),
            "verified_matches": sum(x["verification"]["status"] == "verified_match" for x in findings),
            "candidate_count": len(candidates),
            "elapsed_seconds": round(elapsed, 6),
        },
        "findings": findings,
        "report": report_text,
    }
