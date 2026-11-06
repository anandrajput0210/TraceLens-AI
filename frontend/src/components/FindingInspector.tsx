"use client";

import type { Finding } from "../types";

export default function FindingInspector({
  finding,
  onClose,
  aiResult,
  aiLoading,
  aiError,
}: {
  finding: Finding;
  onClose: () => void;
  aiResult: {
    summary: string;
    impact: string;
    recommendation: string;
  } | null;
  aiLoading: boolean;
  aiError: string;
}) {
  const riskColor =
    finding.context_score >= 90
      ? "text-red-400"
      : finding.context_score >= 75
      ? "text-orange-400"
      : finding.context_score >= 50
      ? "text-yellow-400"
      : "text-gray-400";

  const riskBorder =
    finding.context_score >= 90
      ? "border-red-500/30"
      : finding.context_score >= 75
      ? "border-orange-500/30"
      : "border-white/10";

  return (
    <div className="fixed inset-0 z-50">

      {/* BACKDROP */}

      <button
        aria-label="Close finding inspector"
        onClick={onClose}
        className="absolute inset-0 cursor-default bg-black/70 backdrop-blur-sm"
      />

      {/* PANEL */}

      <aside className="absolute right-0 top-0 h-full w-full max-w-2xl overflow-y-auto border-l border-white/10 bg-[#090b10] shadow-2xl">

        {/* HEADER */}

        <div className="sticky top-0 z-10 border-b border-white/10 bg-[#090b10]/95 px-6 py-5 backdrop-blur">

          <div className="flex items-start justify-between gap-5">

            <div>
              <div className="flex items-center gap-2">

                <span
                  className={`h-2 w-2 rounded-full ${
                    finding.risk_level === "CRITICAL"
                      ? "bg-red-400"
                      : finding.risk_level === "HIGH"
                      ? "bg-orange-400"
                      : finding.risk_level === "MEDIUM"
                      ? "bg-yellow-400"
                      : "bg-gray-500"
                  }`}
                />

                <span className={`text-xs font-semibold uppercase tracking-wider ${riskColor}`}>
                  {finding.risk_level}
                </span>

              </div>

              <h2 className="mt-3 text-xl font-semibold text-white">
                {finding.title}
              </h2>

              <p className="mt-2 font-mono text-xs text-gray-500">
                {finding.id} · {finding.rule_id}
              </p>
            </div>

            <button
              onClick={onClose}
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/10 text-gray-500 transition hover:bg-white/5 hover:text-white"
            >
              ×
            </button>

          </div>
        </div>

        {/* CONTENT */}

        <div className="space-y-6 p-6">

          {/* RISK SCORE */}

          <section className={`rounded-2xl border ${riskBorder} bg-white/[0.02] p-5`}>

            <div className="flex items-end justify-between">

              <div>
                <p className="text-xs uppercase tracking-wider text-gray-600">
                  Context Risk
                </p>

                <p className={`mt-2 font-mono text-5xl font-semibold ${riskColor}`}>
                  {finding.context_score}
                </p>
              </div>

              <div className="text-right">
                <p className="text-xs text-gray-600">
                  Base severity
                </p>

                <p className="mt-1 text-sm text-gray-300">
                  {finding.base_severity}
                </p>
              </div>

            </div>

            <p className="mt-4 text-xs leading-5 text-gray-500">
              Base severity is the scanner rule&apos;s initial assessment. Context risk is a separate prioritization score adjusted by inferred environment, exposure, static reachability, and confidence. Neither score alone proves exploitability.
            </p>

          </section>

          {/* LOCATION */}

          <section>

            <SectionTitle title="Finding location" />

            <div className="rounded-xl border border-white/10 bg-black/20 p-4">

              <p className="font-mono text-sm text-gray-300">
                {finding.file}
              </p>

              <p className="mt-2 text-xs text-gray-600">
                Line {finding.line}
              </p>

            </div>

          </section>

          {/* CONTEXT */}

          <section>

            <SectionTitle title="Application context" />

            <div className="grid grid-cols-3 gap-3">

              <InspectorContext
                label="Environment"
                value={finding.environment}
                confidence={finding.environment_confidence}
              />

              <InspectorContext
                label="Exposure"
                value={finding.exposure}
                confidence={finding.exposure_confidence}
              />

              <InspectorContext
                label="Reachability"
                value={finding.reachability}
              />

            </div>

          </section>

          {finding.environment === "TEST" && finding.category.toLowerCase() === "secrets" && (
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/[0.04] p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-yellow-400/80">
                Test-context review
              </p>
              <p className="mt-2 text-sm leading-6 text-gray-400">
                This credential-like value is in a test or fixture context. TraceLens still reports it because real credentials can be committed to tests. Confirm whether it is synthetic; if it was ever valid, revoke or rotate it.
              </p>
            </div>
          )}

          {/* RISK PATH */}

          {finding.risk_path.length > 0 && (
            <section>

              <SectionTitle title="Static risk path" />

              <div className="rounded-xl border border-white/10 bg-black/30 p-5">

                {finding.risk_path.map((node, index) => (
                  <div key={`${node}-${index}`}>

                    <div className="flex items-center gap-3">

                      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-red-500/20 bg-red-500/5 text-[10px] text-red-400">
                        {index + 1}
                      </div>

                      <div className="break-all font-mono text-xs text-gray-300">
                        {node
                          .replace("file:", "")
                          .replace("route:", "")}
                      </div>

                    </div>

                    {index < finding.risk_path.length - 1 && (
                      <div className="ml-3.5 py-2 text-gray-700">
                        ↓
                      </div>
                    )}

                  </div>
                ))}

              </div>

              <p className="mt-2 text-[11px] leading-5 text-gray-600">
                Static application relationship inferred from repository
                structure. This is not proof of runtime exploitability.
              </p>

            </section>
          )}

          {/* EVIDENCE */}

          <section>

            <SectionTitle title="Evidence" />

            <div className="overflow-x-auto rounded-xl border border-white/10 bg-black/40 p-4">

              <pre className="font-mono text-xs leading-6 text-gray-300">
                {finding.evidence}
              </pre>

            </div>

          </section>

          {/* WHY IT MATTERS */}

          <section>

            <SectionTitle title="Why this matters" />

            <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-5">

              <p className="text-sm leading-7 text-gray-300">

                This finding is prioritized because it is associated
                with{" "}

                <strong className="text-white">
                  {finding.environment}
                </strong>{" "}

                context,{" "}

                <strong className="text-white">
                  {finding.exposure.toLowerCase()}
                </strong>{" "}

                exposure and{" "}

                <strong className="text-white">
                  {finding.reachability.toLowerCase()}
                </strong>{" "}

                static reachability.

              </p>

            </div>

          </section>
          {/* AI SECURITY REASONING */}

<section>
  <SectionTitle title="TraceLens reasoning" />

  <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-5">

    {aiLoading && (
      <div className="space-y-3">
        <p className="text-xs uppercase tracking-wider text-red-400/70">
          Analyzing finding
        </p>

        <p className="text-sm text-gray-400">
          Generating contextual security reasoning...
        </p>

        <div className="h-1.5 overflow-hidden rounded-full bg-white/5">
          <div className="h-full w-1/2 animate-pulse rounded-full bg-red-400" />
        </div>
      </div>
    )}

    {!aiLoading && aiError && (
      <div>
        <p className="text-xs uppercase tracking-wider text-yellow-400/70">
          AI reasoning unavailable
        </p>

        <p className="mt-2 text-sm leading-6 text-gray-400">
          {aiError}
        </p>
      </div>
    )}

    {!aiLoading && !aiError && aiResult && (
      <div className="space-y-5">

        <div>
          <p className="text-[10px] uppercase tracking-wider text-gray-600">
            Summary
          </p>

          <p className="mt-2 text-sm leading-6 text-gray-300">
            {aiResult.summary}
          </p>
        </div>

        <div>
          <p className="text-[10px] uppercase tracking-wider text-gray-600">
            Potential impact
          </p>

          <p className="mt-2 text-sm leading-6 text-gray-300">
            {aiResult.impact}
          </p>
        </div>

        <div>
          <p className="text-[10px] uppercase tracking-wider text-gray-600">
            Recommended fix
          </p>

          <p className="mt-2 text-sm leading-6 text-gray-300">
            {aiResult.recommendation}
          </p>
        </div>

      </div>
    )}

    {!aiLoading && !aiError && !aiResult && (
      <p className="text-sm leading-6 text-gray-500">
        AI reasoning will appear here after the finding is analyzed.
      </p>
    )}

  </div>
</section>

          {/* CONFIDENCE */}

          <section>

            <SectionTitle title="Analysis confidence" />

            <div className="space-y-3">

              <ConfidenceRow
                label="Finding confidence"
                value={finding.confidence}
              />

              <ConfidenceRow
                label="Environment confidence"
                value={finding.environment_confidence}
              />

              <ConfidenceRow
                label="Exposure confidence"
                value={finding.exposure_confidence}
              />

            </div>

          </section>

          {/* REMEDIATION */}

          <section>

            <SectionTitle title="Recommended next step" />

            <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">

              {finding.rule_id === "SEC-001" ? (
                <>
                  <p className="text-sm leading-6 text-gray-300">
                    Remove the credential from source code and move it
                    to an environment variable or managed secret store.
                  </p>

                  <div className="mt-4 rounded-lg border border-white/5 bg-black/40 p-4">

                    <p className="mb-2 text-[10px] uppercase tracking-wider text-gray-600">
                      Preferred pattern
                    </p>

                    <pre className="font-mono text-xs leading-6 text-gray-400">
{`DATABASE_URL = os.getenv("DATABASE_URL")`}
                    </pre>

                  </div>
                </>
              ) : finding.rule_id === "SEC-004" ? (
                <p className="text-sm leading-6 text-gray-300">
                  Disable debug mode for production-facing deployments.
                  Keep development debugging isolated to local environments.
                </p>
              ) : finding.rule_id === "SEC-005" ? (
                <p className="text-sm leading-6 text-gray-300">
                  Replace wildcard CORS origins with an explicit allowlist
                  of trusted application origins.
                </p>
              ) : finding.rule_id === "SEC-007" ? (
                <p className="text-sm leading-6 text-gray-300">
                  Run the container using a dedicated non-root user with
                  only the privileges required by the application.
                </p>
              ) : finding.rule_id === "SEC-008" ? (
                <p className="text-sm leading-6 text-gray-300">
                  Remove credentials from the CI/CD workflow and use the
                  platform&apos;s encrypted secret mechanism instead.
                </p>
              ) : (
                <p className="text-sm leading-6 text-gray-300">
                  Review the detected evidence and apply the least
                  privileged remediation appropriate to this finding.
                </p>
              )}

            </div>

          </section>

        </div>
      </aside>
    </div>
  );
}

function SectionTitle({
  title,
}: {
  title: string;
}) {
  return (
    <p className="mb-3 text-xs uppercase tracking-[0.15em] text-gray-600">
      {title}
    </p>
  );
}

function InspectorContext({
  label,
  value,
  confidence,
}: {
  label: string;
  value: string;
  confidence?: number;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/20 p-4">

      <p className="text-[10px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-2 text-xs font-semibold text-gray-200">
        {value}
      </p>

      {confidence !== undefined && (
        <p className="mt-2 text-[10px] text-gray-600">
          {Math.round(confidence * 100)}% confidence
        </p>
      )}

    </div>
  );
}

function ConfidenceRow({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  const percentage = Math.round(value * 100);

  return (
    <div>

      <div className="mb-2 flex items-center justify-between">

        <span className="text-xs text-gray-500">
          {label}
        </span>

        <span className="font-mono text-xs text-gray-300">
          {percentage}%
        </span>

      </div>

      <div className="h-1.5 overflow-hidden rounded-full bg-white/5">

        <div
          className="h-full rounded-full bg-red-400 transition-all"
          style={{ width: `${percentage}%` }}
        />

      </div>

    </div>
  );
}
