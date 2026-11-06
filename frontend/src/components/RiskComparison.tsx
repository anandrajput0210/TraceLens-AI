"use client";

import type { Finding } from "../types";

export function RiskComparison({
  comparison,
  onSelect,
}: {
  comparison: {
    highest: Finding;
    lowest: Finding;
    delta: number;
  };
  onSelect: (finding: Finding) => void;
}) {
  const { highest, lowest, delta } = comparison;

  return (
    <section className="rounded-2xl border border-white/10 bg-[#0b0d12] p-5">

      <div className="flex items-start justify-between gap-4">

        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-gray-600">
            Context comparison
          </p>

          <h2 className="mt-2 text-lg font-semibold text-white">
            Same finding. Different risk.
          </h2>

          <p className="mt-2 max-w-2xl text-xs leading-5 text-gray-500">
            TraceLens does not treat every occurrence of the same security
            finding equally. Application context changes its priority.
          </p>
        </div>

        <div className="rounded-lg border border-red-500/20 bg-red-500/[0.05] px-3 py-2 text-right">
          <p className="text-[9px] uppercase tracking-wider text-gray-600">
            Risk delta
          </p>

          <p className="font-mono text-xl font-semibold text-red-400">
            +{delta}
          </p>
        </div>

      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2">

        {/* LOWER RISK */}

        <button
          onClick={() => onSelect(lowest)}
          className="rounded-xl border border-white/10 bg-black/20 p-4 text-left transition hover:border-white/20 hover:bg-white/[0.03]"
        >
          <div className="flex items-center justify-between">

            <span className="text-[10px] uppercase tracking-wider text-gray-600">
              Lower contextual risk
            </span>

            <span className="font-mono text-lg text-gray-400">
              {lowest.context_score}
            </span>

          </div>

          <p className="mt-3 truncate text-sm text-gray-200">
            {lowest.title}
          </p>

          <p className="mt-1 truncate font-mono text-[10px] text-gray-600">
            {lowest.file}
          </p>

          <div className="mt-4 grid grid-cols-3 gap-2">

            <ComparisonValue
              label="Environment"
              value={lowest.environment}
            />

            <ComparisonValue
              label="Exposure"
              value={lowest.exposure}
            />

            <ComparisonValue
              label="Reachability"
              value={lowest.reachability}
            />

          </div>

          <p className="mt-4 text-[10px] text-gray-600">
            Click to inspect
          </p>
        </button>

        {/* HIGHER RISK */}

        <button
          onClick={() => onSelect(highest)}
          className="rounded-xl border border-red-500/25 bg-red-500/[0.035] p-4 text-left transition hover:border-red-500/40 hover:bg-red-500/[0.06]"
        >
          <div className="flex items-center justify-between">

            <span className="text-[10px] uppercase tracking-wider text-red-400/70">
              Highest contextual risk
            </span>

            <span className="font-mono text-lg text-red-400">
              {highest.context_score}
            </span>

          </div>

          <p className="mt-3 truncate text-sm text-gray-200">
            {highest.title}
          </p>

          <p className="mt-1 truncate font-mono text-[10px] text-gray-600">
            {highest.file}
          </p>

          <div className="mt-4 grid grid-cols-3 gap-2">

            <ComparisonValue
              label="Environment"
              value={highest.environment}
            />

            <ComparisonValue
              label="Exposure"
              value={highest.exposure}
            />

            <ComparisonValue
              label="Reachability"
              value={highest.reachability}
            />

          </div>

          <p className="mt-4 text-[10px] text-red-400/60">
            Click to inspect
          </p>
        </button>

      </div>

      {/* EXPLANATION */}

      <div className="mt-4 rounded-xl border border-white/10 bg-black/30 p-4">

        <div className="flex gap-3">

          <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-red-500/20 bg-red-500/5 text-xs text-red-400">
            !
          </div>

          <div>

            <p className="text-xs font-medium text-gray-200">
              Why the priority changes
            </p>

            <p className="mt-2 text-xs leading-6 text-gray-500">
              Both findings represent the same class of security issue.
              The difference comes from where they exist in the application:
              environment, exposure and static reachability.
            </p>

            <div className="mt-3 flex flex-wrap gap-2">

              <ContextTag
                label={`Environment: ${highest.environment}`}
              />

              <ContextTag
                label={`Exposure: ${highest.exposure}`}
              />

              <ContextTag
                label={`Reachability: ${highest.reachability}`}
              />

              <ContextTag
                label={`+${delta} contextual risk`}
                danger
              />

            </div>

          </div>

        </div>

      </div>

    </section>
  );
}

function ComparisonValue({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">

      <p className="text-[8px] uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <p className="mt-1 truncate text-[10px] font-medium text-gray-300">
        {value}
      </p>

    </div>
  );
}

function ContextTag({
  label,
  danger = false,
}: {
  label: string;
  danger?: boolean;
}) {
  return (
    <span
      className={`rounded-md border px-2.5 py-1 text-[9px] ${
        danger
          ? "border-red-500/20 bg-red-500/[0.05] text-red-400"
          : "border-white/10 bg-white/[0.02] text-gray-500"
      }`}
    >
      {label}
    </span>
  );
}

export function RiskBreakdownModal({
  highest,
  lowest,
  delta,
  onClose,
}: {
  highest: Finding;
  lowest: Finding;
  delta: number;
  onClose: () => void;
}) {
  const changes = [
    {
      label: "Environment",
      from: lowest.environment,
      to: highest.environment,
      fromConfidence: lowest.environment_confidence,
      toConfidence: highest.environment_confidence,
    },
    {
      label: "Exposure",
      from: lowest.exposure,
      to: highest.exposure,
      fromConfidence: lowest.exposure_confidence,
      toConfidence: highest.exposure_confidence,
    },
    {
      label: "Reachability",
      from: lowest.reachability,
      to: highest.reachability,
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4 backdrop-blur-sm">

      <div className="w-full max-w-2xl overflow-hidden rounded-2xl border border-white/10 bg-[#0b0d12] shadow-2xl">

        {/* HEADER */}

        <div className="flex items-start justify-between border-b border-white/10 p-6">

          <div>
            <p className="text-[10px] uppercase tracking-[0.18em] text-gray-600">
              Context Risk Analysis
            </p>

            <h2 className="mt-2 text-xl font-semibold text-white">
              Why did the risk change?
            </h2>

            <p className="mt-2 text-xs leading-5 text-gray-500">
              TraceLens found the same finding class in two different
              application contexts.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-white/10 text-gray-500 transition hover:bg-white/5 hover:text-white"
          >
            ×
          </button>

        </div>

        {/* SCORE HEADER */}

        <div className="grid grid-cols-3 gap-3 p-6">

          <div className="rounded-xl border border-white/10 bg-black/20 p-4">

            <p className="text-[9px] uppercase tracking-wider text-gray-600">
              Lower context
            </p>

            <p className="mt-2 font-mono text-3xl text-gray-400">
              {lowest.context_score}
            </p>

            <p className="mt-1 text-[10px] text-gray-600">
              {lowest.risk_level}
            </p>

          </div>

          <div className="flex items-center justify-center">

            <div className="text-center">

              <p className="text-[9px] uppercase tracking-wider text-gray-600">
                Risk delta
              </p>

              <p className="font-mono text-2xl font-semibold text-red-400">
                +{delta}
              </p>

            </div>

          </div>

          <div className="rounded-xl border border-red-500/20 bg-red-500/[0.035] p-4">

            <p className="text-[9px] uppercase tracking-wider text-red-400/60">
              Higher context
            </p>

            <p className="mt-2 font-mono text-3xl text-red-400">
              {highest.context_score}
            </p>

            <p className="mt-1 text-[10px] text-red-400/60">
              {highest.risk_level}
            </p>

          </div>

        </div>

        {/* COMPARISON */}

        <div className="px-6 pb-6">

          <div className="overflow-hidden rounded-xl border border-white/10">

            <div className="grid grid-cols-[1fr_1fr_1fr] border-b border-white/10 bg-white/[0.025] px-4 py-3">

              <span className="text-[9px] uppercase tracking-wider text-gray-600">
                Context signal
              </span>

              <span className="text-[9px] uppercase tracking-wider text-gray-600">
                Lower risk
              </span>

              <span className="text-[9px] uppercase tracking-wider text-gray-600">
                Higher risk
              </span>

            </div>

            {changes.map((change) => (
              <div
                key={change.label}
                className="grid grid-cols-[1fr_1fr_1fr] items-center border-b border-white/5 px-4 py-4 last:border-0"
              >

                <span className="text-xs font-medium text-gray-300">
                  {change.label}
                </span>

                <div>
                  <p className="text-xs text-gray-500">
                    {change.from}
                  </p>

                  {change.fromConfidence !== undefined && (
                    <p className="mt-1 text-[9px] text-gray-700">
                      {Math.round(change.fromConfidence * 100)}% confidence
                    </p>
                  )}
                </div>

                <div>
                  <p className="text-xs font-medium text-red-400">
                    {change.to}
                  </p>

                  {change.toConfidence !== undefined && (
                    <p className="mt-1 text-[9px] text-gray-700">
                      {Math.round(change.toConfidence * 100)}% confidence
                    </p>
                  )}
                </div>

              </div>
            ))}

          </div>

        </div>

        {/* EXPLANATION */}

        <div className="border-t border-white/10 bg-black/20 p-6">

          <p className="text-[10px] uppercase tracking-[0.15em] text-gray-600">
            TraceLens reasoning
          </p>

          <p className="mt-3 text-sm leading-6 text-gray-300">
            Both findings belong to the same security category, but their
            application context is different.
          </p>

          <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/[0.035] p-4">

            <p className="text-xs font-medium text-gray-200">
              {highest.file}
            </p>

            <p className="mt-2 text-xs leading-5 text-gray-500">
              This occurrence is associated with{" "}
              <span className="text-gray-300">
                {highest.environment.toLowerCase()}
              </span>{" "}
              context,{" "}
              <span className="text-gray-300">
                {highest.exposure.toLowerCase()}
              </span>{" "}
              exposure and{" "}
              <span className="text-gray-300">
                {highest.reachability.toLowerCase()}
              </span>{" "}
              static reachability.
            </p>

          </div>

          <p className="mt-4 text-[10px] leading-5 text-gray-600">
            TraceLens uses repository evidence and static application
            relationships to estimate contextual risk. This does not prove
            runtime exploitability.
          </p>

        </div>

      </div>

    </div>
  );
}
