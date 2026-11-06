"use client";

import { useMemo, useState } from "react";
import { API_BASE_URL } from "../lib/api";
import type { Analysis, Finding, ScoringPolicy } from "../types";
import FindingInspector from "./FindingInspector";
import { RiskComparison, RiskBreakdownModal } from "./RiskComparison";

export default function Dashboard({
  analysis,
  onReset,
}: {
  analysis: Analysis;
  onReset: () => void;
}) {
  const [selectedFinding, setSelectedFinding] =
  useState<Finding | null>(null);
  const comparison = useMemo(() => {
  const allCredentialFindings = analysis.findings.filter(
    (finding) => finding.rule_id === "SEC-001"
  );

  // Only compare findings of the same kind (same title), so a provider
  // token is never compared with a generic password finding.
  const topCredential = [...allCredentialFindings].sort(
    (a, b) => b.context_score - a.context_score
  )[0];

  const credentialFindings = topCredential
    ? allCredentialFindings.filter(
        (finding) => finding.title === topCredential.title
      )
    : [];

  if (credentialFindings.length < 2) {
    return null;
  }

  const highest = [...credentialFindings].sort(
    (a, b) => b.context_score - a.context_score
  )[0];

  const lowest = [...credentialFindings].sort(
    (a, b) => a.context_score - b.context_score
  )[0];

  if (highest.id === lowest.id) {
    return null;
  }

  return {
    highest,
    lowest,
    delta: highest.context_score - lowest.context_score,
  };
}, [analysis.findings]);
  const sortedFindings = useMemo(
    () =>
      [...analysis.findings].sort(
        (a, b) => b.context_score - a.context_score
      ),
    [analysis.findings]
  );
const [aiResult, setAiResult] = useState<{
  summary: string;
  impact: string;
  recommendation: string;
} | null>(null);

const [aiLoading, setAiLoading] = useState(false);
const [aiError, setAiError] = useState("");
async function analyzeWithAI(finding: Finding) {
  setAiLoading(true);
  setAiError("");
  setAiResult(null);

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/ai/explain`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          finding: {
            id: finding.id,
            rule_id: finding.rule_id,
            title: finding.title,
            category: finding.category,
            file: finding.file,
            line: finding.line,
            evidence: finding.evidence,
            base_severity: finding.base_severity,
            confidence: finding.confidence,
            environment: finding.environment,
            environment_confidence:
              finding.environment_confidence,
            exposure: finding.exposure,
            exposure_confidence:
              finding.exposure_confidence,
            reachability: finding.reachability,
            context_score: finding.context_score,
            risk_level: finding.risk_level,
            risk_path: finding.risk_path,
          },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(
        `AI request failed: ${response.status}`
      );
    }

    const data = await response.json();

    setAiResult({
      summary: data.summary,
      impact: data.impact,
      recommendation: data.recommendation,
    });
  } catch (error) {
    console.error(error);

    setAiError(
      "AI reasoning is currently unavailable. The deterministic TraceLens analysis is still valid."
    );
  } finally {
    setAiLoading(false);
  }
}
function handleSelectFinding(finding: Finding) {
  setSelectedFinding(finding);
  analyzeWithAI(finding);
}
  const topFinding = sortedFindings[0];
const [showRiskBreakdown, setShowRiskBreakdown] = useState(false);

  const critical = analysis.findings.filter(
    (f) => f.risk_level === "CRITICAL"
  ).length;

  const high = analysis.findings.filter(
    (f) => f.risk_level === "HIGH"
  ).length;

  const medium = analysis.findings.filter(
    (f) => f.risk_level === "MEDIUM"
  ).length;

  const low = analysis.findings.filter(
    (f) => f.risk_level === "LOW"
  ).length;

  const sameRule = analysis.findings.filter(
    (f) =>
      f.rule_id === topFinding?.rule_id &&
      f.title === topFinding?.title
  );

  const lowestSameRule = [...sameRule].sort(
    (a, b) => a.context_score - b.context_score
  )[0];


  const riskDelta =
    topFinding && lowestSameRule
      ? topFinding.context_score -
        lowestSameRule.context_score
      : 0;

  return (
    <main className="min-h-screen bg-[#07090d] text-white">

      {/* HEADER */}

      <header className="border-b border-white/5">

        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">

          <div className="flex items-center gap-3">

            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10 text-sm font-bold text-red-400">
              TL
            </div>

            <div>
              <div className="font-semibold">
                TraceLens
              </div>

              <div className="text-xs text-gray-600">
                Security Risk Intelligence
              </div>
            </div>

          </div>

          <button
            onClick={onReset}
            className="rounded-lg border border-white/10 px-4 py-2 text-xs text-gray-400 transition hover:bg-white/5 hover:text-white"
          >
            Analyze another repository
          </button>

        </div>

      </header>


      {/* MAIN */}

      <section className="mx-auto max-w-7xl px-6 py-8">

        <div className="mb-8 flex flex-wrap items-end justify-between gap-6">
<div>

          <p className="text-xs uppercase tracking-[0.2em] text-gray-600">
            Application analysis
          </p>

          <h1 className="mt-2 text-3xl font-semibold">
            {analysis.repository}
          </h1>

          <p className="mt-2 text-sm text-gray-500">
            {analysis.files_analyzed} files analyzed ·{" "}
            {analysis.findings_count} findings
          </p>

        </div>

{analysis.findings.length > 0 && (
  <div className="text-right" title="The overall score is the highest score among all findings">
    <div className={`font-mono text-4xl font-semibold ${levelText(analysis.risk_level)}`}>
      {analysis.overall_score}
    </div>
    <div className="text-xs text-gray-500">
      overall: {analysis.risk_level.toLowerCase()} (highest finding)
    </div>
  </div>
)}
</div>


        {/* LEVEL COUNTS */}

        {analysis.findings.length > 0 && (
        <ul className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-gray-400">
          {([
            ["Critical", critical, "CRITICAL"],
            ["High", high, "HIGH"],
            ["Medium", medium, "MEDIUM"],
            ["Low", low, "LOW"],
          ] as const).map(([label, count, level]) => (
            <li key={label} className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${levelDot(level)}`} />
              <span className="font-mono text-white">{count}</span>
              {label}
            </li>
          ))}
        </ul>
        )}


        {/* VERDICT */}

        {analysis.findings.length === 0 ? (
          <section className="mt-6 rounded-2xl border border-white/10 bg-white/[0.025] p-8">
            <h2 className="text-xl font-semibold">
              {analysis.files_analyzed === 0 ? "No supported files found" : "Nothing to fix"}
            </h2>
            <p className="mt-2 max-w-xl text-sm leading-6 text-gray-400">
              {analysis.files_analyzed === 0
                ? "TraceLens did not find any file types it can scan. Check that you uploaded the project folder, not only build output."
                : `TraceLens checked ${analysis.files_analyzed} file${analysis.files_analyzed === 1 ? "" : "s"} and found no findings. It only reads file types it supports, so this does not cover everything in the repository.`}
            </p>
          </section>
        ) : (
        <div className="mt-6 grid items-start gap-6 lg:grid-cols-[1.2fr_1fr]">

          {topFinding && (
            <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-6">

              <p className="text-sm text-gray-500">Fix this first</p>

              <div className="mt-3 flex items-start justify-between gap-6">
                <div>
                  <h2 className="text-2xl font-semibold">{topFinding.title}</h2>
                  <p className="mt-2 font-mono text-xs text-gray-500">
                    {topFinding.file}:{topFinding.line}
                  </p>
                </div>

                <div className="text-right">
                  <div className={`font-mono text-5xl font-semibold ${levelText(topFinding.risk_level)}`}>
                    {topFinding.context_score}
                  </div>
                  <div className="mt-1 text-xs text-gray-500">
                    {topFinding.risk_level.toLowerCase()} in context
                  </div>
                  {topFinding.base_severity.toUpperCase() !==
                    topFinding.risk_level.toUpperCase() && (
                    <div className="text-xs text-gray-600">
                      rule severity: {topFinding.base_severity.toLowerCase()}
                    </div>
                  )}
                </div>
              </div>

              <p className="mt-5 max-w-xl text-sm leading-6 text-gray-300">
                {whyFirst(topFinding)}
              </p>

              <div className="mt-5 grid grid-cols-3 gap-3">
                <ContextBox
                  label="Environment"
                  value={topFinding.environment}
                  confidence={topFinding.environment_confidence}
                />
                <ContextBox
                  label="Exposure"
                  value={topFinding.exposure}
                  confidence={topFinding.exposure_confidence}
                />
                <ContextBox
                  label="Reachability"
                  value={topFinding.reachability}
                />
              </div>

              {topFinding.risk_path.length > 0 && (
                <ol className="mt-5 space-y-1 rounded-xl border border-white/5 bg-black/30 p-4 font-mono text-xs text-gray-300">
                  {topFinding.risk_path.map((node, index) => (
                    <li key={`${node}-${index}`}>
                      {index > 0 && <span className="text-gray-600">↳ </span>}
                      {node.replace("file:", "").replace("route:", "")}
                    </li>
                  ))}
                </ol>
              )}

              <p className="mt-5 text-xs leading-5 text-gray-600">
                Estimated from repository evidence and static relationships.
                This is not proof that the issue can be exploited at runtime.
              </p>

            </section>
          )}

          <ScoreLadder
            findings={analysis.findings}
            top={topFinding}
            lowest={lowestSameRule}
            delta={riskDelta}
            policy={analysis.scoring_policy ?? FALLBACK_POLICY}
            onExplain={() => setShowRiskBreakdown(true)}
          />

        </div>
        )}


        {/* CONTEXT COMPARISON */}

        {comparison && (
          <section className="mt-6">
            <RiskComparison
  comparison={comparison}
  onSelect={handleSelectFinding}
/>
          </section>
        )}

        {/* FINDINGS */}

        <section className="mt-8">

          <div className="mb-4 flex items-center justify-between">

            <div>

              <p className="text-xs uppercase tracking-wider text-gray-600">
                Findings
              </p>

              <h2 className="mt-1 text-xl font-medium">
                All detected risks
              </h2>

            </div>

            <span className="text-xs text-gray-600">
              Sorted by Context Risk
            </span>

          </div>


          <div className="overflow-hidden rounded-2xl border border-white/10">

{sortedFindings.map((finding, index) => (
  <button
    key={finding.id}
onClick={() => handleSelectFinding(finding)}
    className={`group flex w-full items-center justify-between gap-5 px-5 py-4 text-left transition ${
      index !== sortedFindings.length - 1
        ? "border-b border-white/5"
        : ""
    } ${
      selectedFinding?.id === finding.id
        ? "bg-red-500/[0.06]"
        : "hover:bg-white/[0.03]"
    }`}
  >
    <div className="flex min-w-0 items-center gap-4">

      <div
        className={`h-2.5 w-2.5 shrink-0 rounded-full ${
          finding.risk_level === "CRITICAL"
            ? "bg-red-400 shadow-[0_0_10px_rgba(248,113,113,0.6)]"
            : finding.risk_level === "HIGH"
            ? "bg-orange-400"
            : finding.risk_level === "MEDIUM"
            ? "bg-yellow-400"
            : "bg-gray-500"
        }`}
      />

      <div className="min-w-0">
        <div className="truncate text-sm text-gray-200 group-hover:text-white">
          {finding.title}
        </div>

        <div className="mt-1 truncate font-mono text-xs text-gray-600">
          {finding.file}:{finding.line}
        </div>
      </div>
    </div>

    <div className="flex shrink-0 items-center gap-5">

      <span className="hidden text-xs text-gray-600 md:block">
        {finding.environment}
      </span>

      <span className="hidden text-xs text-gray-600 md:block">
        {finding.reachability}
      </span>

      <span
        className={`font-mono text-sm ${
          finding.context_score >= 90
            ? "text-red-400"
            : finding.context_score >= 75
            ? "text-orange-400"
            : finding.context_score >= 50
            ? "text-yellow-400"
            : "text-gray-400"
        }`}
      >
        {finding.context_score}
      </span>

      <span className="text-gray-700 transition group-hover:text-gray-300">
        →
      </span>
    </div>
  </button>
))}
          </div>

        </section>

      </section>
      {selectedFinding && (
  <FindingInspector
  finding={selectedFinding}
  onClose={() => setSelectedFinding(null)}
  aiResult={aiResult}
  aiLoading={aiLoading}
  aiError={aiError}
/>
)}
    {showRiskBreakdown &&
  topFinding &&
  lowestSameRule && (
    <RiskBreakdownModal
      highest={topFinding}
      lowest={lowestSameRule}
      delta={riskDelta}
      onClose={() => setShowRiskBreakdown(false)}
    />
  )}
    </main>
  );
}

function ContextBox({
  label,
  value,
  confidence,
}: {
  label: string;
  value: string;
  confidence?: number;
}) {
  return (
    <div className="rounded-xl border border-white/5 bg-black/20 p-3">

      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-2 text-xs font-medium text-gray-300">
        {value}
      </p>

      {confidence !== undefined && (
        <p className="mt-1 text-[10px] text-gray-600">
          {Math.round(confidence * 100)}% confidence
        </p>
      )}

    </div>
  );
}

export function Feature({
  number,
  title,
  description,
}: {
  number: string;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-6">

      <div className="mb-8 font-mono text-xs text-gray-600">
        {number}
      </div>

      <h2 className="text-lg font-medium">
        {title}
      </h2>

      <p className="mt-3 text-sm leading-6 text-gray-500">
        {description}
      </p>

    </div>
  );
}


const CONTEXT_FACTORS = ["environment", "exposure", "reachability"] as const;

// Only used for results that predate the backend's scoring_policy.
const FALLBACK_POLICY: ScoringPolicy = {
  levels: [
    { level: "LOW", min: 25 },
    { level: "MEDIUM", min: 50 },
    { level: "HIGH", min: 75 },
    { level: "CRITICAL", min: 90 },
  ],
  critical_floor: { default: 75, test: 60 },
};

const BAND_TINTS: Record<string, string> = {
  INFO: "bg-white/[0.04]",
  LOW: "bg-sky-400/10",
  MEDIUM: "bg-yellow-400/10",
  HIGH: "bg-orange-400/15",
  CRITICAL: "bg-red-500/20",
};

function buildBands(policy: ScoringPolicy) {
  const levels = [...policy.levels].sort((x, y) => x.min - y.min);
  const bands = [
    { label: "info", from: 0, to: levels[0]?.min ?? 100, tint: BAND_TINTS.INFO },
  ];
  levels.forEach((entry, index) =>
    bands.push({
      label: entry.level.toLowerCase(),
      from: entry.min,
      to: levels[index + 1]?.min ?? 100,
      tint: BAND_TINTS[entry.level] ?? "",
    })
  );
  return bands;
}

const clampScore = (score: number) => Math.min(100, Math.max(0, score));
const percent = (value: number) => `${Math.round(value * 100)}%`;
// The engine scores with the lowest of these three confidences.
const effectiveConfidence = (f: Finding) =>
  Math.min(f.confidence, f.environment_confidence, f.exposure_confidence);

function joinList(items: string[]) {
  return items.length < 3
    ? items.join(" and ")
    : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

function levelDot(level: string) {
  return (
    { CRITICAL: "bg-red-500", HIGH: "bg-orange-400", MEDIUM: "bg-yellow-400", LOW: "bg-sky-400" } as Record<string, string>
  )[level.toUpperCase()] ?? "bg-gray-500";
}

function levelText(level: string) {
  return (
    { CRITICAL: "text-red-400", HIGH: "text-orange-400", MEDIUM: "text-yellow-300", LOW: "text-sky-300" } as Record<string, string>
  )[level.toUpperCase()] ?? "text-gray-300";
}

// Explains the ranking using only what is actually known about the finding.
function whyFirst(finding: Finding) {
  const known: string[] = [];
  const unknown: string[] = [];

  for (const factor of CONTEXT_FACTORS) {
    const value = finding[factor];
    (value.toUpperCase() === "UNKNOWN" ? unknown : known).push(
      `${value.toLowerCase()} ${factor}`
    );
  }

  const first = known.length
    ? `Ranked first because of its ${known.join(", ")}.`
    : "Ranked first on rule severity alone.";

  const second = unknown.length
    ? ` The repository did not show its ${unknown
        .map((item) => item.split(" ")[1])
        .join(", ")}, so those add only partial weight.`
    : "";

  return first + second;
}

// A 0-100 scale of every finding. The span between the top finding and the
// same finding in its lowest-scoring context shows what context changed.
function ScoreLadder({
  findings,
  top,
  lowest,
  delta,
  policy,
  onExplain,
}: {
  findings: Finding[];
  top?: Finding;
  lowest?: Finding;
  delta: number;
  policy: ScoringPolicy;
  onExplain: () => void;
}) {
  const bands = buildBands(policy);

  // Findings with the same score share one mark, with a count badge.
  const groups = new Map<number, Finding[]>();
  for (const finding of findings) {
    const key = clampScore(finding.context_score);
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  const allTied = groups.size === 1 && findings.length > 1;

  const hasPair = !!top && !!lowest && delta > 0;

  const reasons: string[] = [];
  if (top && lowest) {
    for (const factor of CONTEXT_FACTORS) {
      if (top[factor] !== lowest[factor]) {
        reasons.push(
          `its ${factor} is ${top[factor].toLowerCase()}, not ${lowest[factor].toLowerCase()}`
        );
      }
    }
    if (Math.abs(effectiveConfidence(top) - effectiveConfidence(lowest)) >= 0.01) {
      reasons.push(
        `the scan is ${percent(effectiveConfidence(top))} confident, not ${percent(effectiveConfidence(lowest))}`
      );
    }
  }

  const onFloor =
    !!top &&
    top.base_severity.toUpperCase() === "CRITICAL" &&
    top.environment.toUpperCase() !== "TEST" &&
    top.context_score === policy.critical_floor.default;

  return (
    <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-6">

      <h2 className="text-lg font-medium">Where every finding lands</h2>
      <p className="mt-1 text-sm text-gray-500">
        Each mark is one finding, scored 0 to 100 using its context.
      </p>

      <div className="relative mt-10 h-14" role="img" aria-label="Score scale from 0 to 100. Findings with equal scores share a marker; count badges show how many.">

        <div className="absolute inset-x-0 bottom-0 flex h-3 overflow-hidden rounded-full">
          {bands.map((band) => (
            <div
              key={band.label}
              className={band.tint}
              style={{ width: `${band.to - band.from}%` }}
            />
          ))}
        </div>

        {hasPair && (
          <div
            className="absolute bottom-[5px] h-[2px] bg-amber-300/80"
            style={{
              left: `${clampScore(lowest!.context_score)}%`,
              width: `${clampScore(top!.context_score) - clampScore(lowest!.context_score)}%`,
            }}
          />
        )}

        {[...groups.entries()].map(([score, group]) => (
          <span
            key={score}
            className="absolute bottom-0 flex -translate-x-1/2 flex-col items-center"
            style={{ left: `${score}%` }}
            title={group.map((f) => `${f.title}: ${f.context_score}`).join("\n")}
          >
            {group.length > 1 && (
              <span className="mb-1 rounded-full bg-white/15 px-1.5 text-[10px] leading-4 text-white">
                {group.length}
              </span>
            )}
            <span
              className={`w-[3px] rounded-full ${
                group.some((f) => f.id === top?.id)
                  ? "h-8 bg-white"
                  : "h-5 bg-white/40"
              }`}
            />
          </span>
        ))}

      </div>

      <div className="mt-1 flex text-[11px] text-gray-600">
        {bands.map((band) => (
          <span key={band.label} style={{ width: `${band.to - band.from}%` }}>
            {band.label}
          </span>
        ))}
      </div>

      {allTied && (
        <p className="mt-3 text-xs text-gray-500">
          All {findings.length} findings score{" "}
          {[...groups.keys()][0]}, so their order is a tie.
        </p>
      )}

      {hasPair ? (
        <button
          type="button"
          onClick={onExplain}
          className="mt-7 w-full rounded-xl border border-amber-300/20 bg-amber-300/[0.04] p-4 text-left transition hover:border-amber-300/50"
        >
          <p className="text-sm text-gray-300">
            The same finding scores{" "}
            <span className="font-mono text-amber-200">{delta} points</span>{" "}
            higher in {top!.file} because{" "}
            {reasons.length ? joinList(reasons) : "other scoring inputs differ"}.
          </p>
          {onFloor && (
            <p className="mt-2 text-xs text-gray-500">
              Includes the minimum score of {policy.critical_floor.default} that critical findings get outside test files.
            </p>
          )}
          <p className="mt-3 text-xs text-amber-200/80">See the breakdown</p>
        </button>
      ) : (
        <p className="mt-7 text-sm text-gray-500">
          {top && lowest
            ? `The matching findings are tied at ${clampScore(top.context_score)}; no contextual score difference is available.`
            : top
              ? "Only one occurrence of the top finding type is available for comparison."
              : "No findings are available to compare."}
        </p>
      )}

    </section>
  );
}
