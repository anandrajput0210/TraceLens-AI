import shutil
import uuid
from pathlib import Path

from app.scanner.engine import ScannerEngine
from app.services.repository_service import discover_files
from app.utils.redaction import redact_evidence


ANALYSES = {}


def serialize_finding(finding):
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": finding.category,
        "file": finding.file.replace("\\", "/"),
        "line": finding.line,

        # Never expose raw credentials through the API.
        "evidence": redact_evidence(
            finding.evidence
        ),

        "base_severity": finding.base_severity,
        "confidence": finding.confidence,

        "environment": finding.environment,
        "environment_confidence": finding.environment_confidence,

        "exposure": finding.exposure,
        "exposure_confidence": finding.exposure_confidence,

        "reachability": finding.reachability,

        "context_score": finding.context_score,
        "risk_level": finding.risk_level,

        "risk_path": [
            node.replace("\\", "/")
            for node in finding.risk_path
        ],
    }


def run_analysis(
    analysis_id: str,
    repository_path: str,
    repository_name: str,
):
    """
    Run TraceLens against a repository.

    Repository source code is analyzed as data.
    It is never executed.
    """

    try:
        ANALYSES[analysis_id]["status"] = "scanning"
        ANALYSES[analysis_id]["progress"] = 25

        # -----------------------------------------------------
        # Discover repository files
        # -----------------------------------------------------

        files = discover_files(
            repository_path
        )

        ANALYSES[analysis_id]["status"] = "analyzing"
        ANALYSES[analysis_id]["progress"] = 50

        # -----------------------------------------------------
        # Run TraceLens scanner
        # -----------------------------------------------------

        engine = ScannerEngine()

        findings = engine.scan_repository(
            repository_path,
            files,
        )

        # ScannerEngine isolates individual scanner failures
        # and stores them in engine.errors.
        scanner_errors = engine.errors

        # If scanner components failed but the overall analysis
        # still produced results, mark the analysis as partial.
        analysis_status = (
            "partial"
            if scanner_errors
            else "completed"
        )

        # -----------------------------------------------------
        # Put highest-context risks first.
        # -----------------------------------------------------

        findings = sorted(
            findings,
            key=lambda finding: finding.context_score,
            reverse=True,
        )

        # -----------------------------------------------------
        # Overall application risk
        # -----------------------------------------------------

        overall_score = max(
            (
                finding.context_score
                for finding in findings
            ),
            default=0,
        )

        if overall_score >= 90:
            overall_level = "CRITICAL"

        elif overall_score >= 75:
            overall_level = "HIGH"

        elif overall_score >= 50:
            overall_level = "MEDIUM"

        elif overall_score >= 25:
            overall_level = "LOW"

        else:
            overall_level = "INFO"

        # -----------------------------------------------------
        # Store analysis result
        # -----------------------------------------------------

        ANALYSES[analysis_id] = {
            "analysis_id": analysis_id,
            "status": analysis_status,
            "progress": 100,
            "repository": repository_name,
            "files_analyzed": len(files),
            "findings_count": len(findings),
            "overall_score": overall_score,
            "risk_level": overall_level,

            "findings": [
                serialize_finding(finding)
                for finding in findings
            ],

            # Scanner errors are exposed so the frontend can
            # distinguish a complete analysis from a partial one.
            "errors": scanner_errors,
        }

    except Exception as error:

        ANALYSES[analysis_id] = {
            "analysis_id": analysis_id,
            "status": "failed",
            "progress": 100,
            "error": str(error),
        }

    finally:

        # -----------------------------------------------------
        # Remove temporary repository after analysis.
        # -----------------------------------------------------

        try:
            shutil.rmtree(
                repository_path,
                ignore_errors=True,
            )

        except Exception:
            pass


def create_analysis(
    repository_path: str,
):
    analysis_id = str(
        uuid.uuid4()
    )[:8]

    repository_name = Path(
        repository_path
    ).name

    ANALYSES[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "queued",
        "progress": 0,
        "repository": repository_name,
    }

    return analysis_id