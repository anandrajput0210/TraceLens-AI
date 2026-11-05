from app.models.finding import Finding
from app.utils.redaction import redact_evidence
from app.graph.builder import ApplicationGraphBuilder
from app.graph.traversal import find_public_risk_path

from app.risk.context import detect_environment
from app.risk.exposure import detect_exposure
from app.risk.scoring import calculate_context_risk

from app.scanner.secrets import (
    scan_hardcoded_credentials,
    scan_high_entropy_strings,
)
from app.scanner.config import scan_config_security
from app.scanner.docker import scan_dockerfile
from app.scanner.ci import scan_ci_workflow
from app.scanner.endpoints import scan_sensitive_endpoints


class ScannerEngine:

    def __init__(self):
        self.finding_counter = 0
        self.errors = []

    # =========================================================
    # FINDING ID
    # =========================================================

    def _next_id(self) -> str:
        self.finding_counter += 1
        return f"F{self.finding_counter:03d}"

    # =========================================================
    # SAFE SCANNER EXECUTION
    # =========================================================

    def _run_scanner(
        self,
        scanner,
        absolute_path: str,
        relative_path: str,
        rule_id: str,
    ) -> list[dict]:

        try:
            return scanner(
                absolute_path,
                relative_path,
            )

        except Exception as exc:

            error = {
                "rule_id": rule_id,
                "file": relative_path,
                "error": redact_evidence(str(exc)),
            }

            self.errors.append(error)

            return []

    # =========================================================
    # FINDING DEDUPLICATION
    # =========================================================

    def _deduplicate_findings(
        self,
        findings: list[dict],
    ) -> list[dict]:
        """
        Remove exact duplicate findings.

        Findings are considered duplicates only when they have
        the same:

        - rule_id
        - file
        - line
        - evidence

        Different security rules are intentionally preserved,
        even when they point to the same location.
        """

        unique_findings = []
        seen = set()

        for finding in findings:

            key = (
                finding.get("rule_id"),
                finding.get("file"),
                finding.get("line"),
                finding.get("evidence"),
            )

            if key in seen:
                continue

            seen.add(key)
            unique_findings.append(finding)

        return unique_findings

    # =========================================================
    # MAIN REPOSITORY SCAN
    # =========================================================

    def scan_repository(
        self,
        repository_path: str,
        files: list[dict],
    ) -> list[Finding]:

        # =====================================================
        # 1. Build application graph once
        # =====================================================

        graph_builder = ApplicationGraphBuilder()

        graph = graph_builder.build(files)

        all_findings = []

        # =====================================================
        # 2. Scan every supported file
        # =====================================================

        for file_info in files:

            absolute_path = file_info["absolute_path"]
            relative_path = file_info["path"]

            raw_findings = []

            # =================================================
            # SEC-001
            # Hardcoded credentials
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_hardcoded_credentials,
                    absolute_path,
                    relative_path,
                    "SEC-001",
                )
            )

            # =================================================
            # SEC-002
            # High-entropy hardcoded strings
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_high_entropy_strings,
                    absolute_path,
                    relative_path,
                    "SEC-002",
                )
            )

            # =================================================
            # SEC-003 / SEC-004 / SEC-005
            # Configuration security
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_config_security,
                    absolute_path,
                    relative_path,
                    "SEC-CONFIG",
                )
            )

            # =================================================
            # SEC-006
            # Sensitive / potentially unprotected endpoint
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_sensitive_endpoints,
                    absolute_path,
                    relative_path,
                    "SEC-006",
                )
            )

            # =================================================
            # SEC-007
            # Docker root execution
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_dockerfile,
                    absolute_path,
                    relative_path,
                    "SEC-007",
                )
            )

            # =================================================
            # SEC-008
            # CI/CD credential exposure
            # =================================================

            raw_findings.extend(
                self._run_scanner(
                    scan_ci_workflow,
                    absolute_path,
                    relative_path,
                    "SEC-008",
                )
            )

            # =================================================
            # DEDUPLICATE RAW FINDINGS
            #
            # Do this BEFORE converting them into Finding
            # objects.
            # =================================================

            raw_findings = self._deduplicate_findings(
                raw_findings
            )

            # =================================================
            # 3. Convert raw findings into Finding objects
            # =================================================

            for raw in raw_findings:

                # ---------------------------------------------
                # Environment
                # ---------------------------------------------

                (
                    environment,
                    environment_confidence,
                ) = detect_environment(
                    relative_path
                )

                # ---------------------------------------------
                # Direct exposure evidence
                # ---------------------------------------------

                (
                    exposure,
                    exposure_confidence,
                ) = detect_exposure(
                    absolute_path
                )

                # ---------------------------------------------
                # Application relationship / reachability hint
                # A static import path to a route is not proof that the finding's
                # vulnerable code is executed or that the route is internet-facing.
                risk_path = find_public_risk_path(
                    graph,
                    relative_path,
                )

                if risk_path:
                    # Keep this heuristic below HIGH until data-flow or runtime
                    # reachability is actually established.
                    reachability = "MEDIUM"
                else:
                    # NONE means no path was found by this graph, not proof that
                    # the issue is unreachable in a running deployment.
                    reachability = "UNKNOWN"

                # Combined confidence
                # ---------------------------------------------

                confidence = min(
                    raw["confidence"],
                    environment_confidence,
                    exposure_confidence,
                )

                # ---------------------------------------------
                # Context Risk
                # ---------------------------------------------

                risk = calculate_context_risk(
                    base_severity=raw["base_severity"],
                    exposure=exposure,
                    reachability=reachability,
                    environment=environment,
                    confidence=confidence,
                )

                # ---------------------------------------------
                # Final Finding
                # ---------------------------------------------

                finding = Finding(
                    id=self._next_id(),

                    rule_id=raw["rule_id"],

                    title=raw["title"],

                    category=raw["category"],

                    file=raw["file"],

                    line=raw["line"],

                    evidence=raw["evidence"],

                    base_severity=raw["base_severity"],

                    confidence=raw["confidence"],

                    environment=environment,

                    environment_confidence=(
                        environment_confidence
                    ),

                    exposure=exposure,

                    exposure_confidence=(
                        exposure_confidence
                    ),

                    reachability=reachability,

                    context_score=risk.score,

                    risk_level=risk.level,

                    risk_path=risk_path,
                )

                all_findings.append(
                    finding
                )

        # =====================================================
        # 4. Return Finding objects
        # =====================================================

        return all_findings