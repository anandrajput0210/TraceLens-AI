"use client";

import { useEffect, useMemo, useState } from "react";

type Finding = {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  file: string;
  line: number;
  evidence: string;
  base_severity: string;
  confidence: number;
  environment: string;
  environment_confidence: number;
  exposure: string;
  exposure_confidence: number;
  reachability: string;
  context_score: number;
  risk_level: string;
  risk_path: string[];
};

type Analysis = {
  analysis_id: string;
  status: string;
  progress: number;
  repository: string;
  files_analyzed: number;
  findings_count: number;
  overall_score: number;
  risk_level: string;
  findings: Finding[];
  errors?: {
    rule_id: string;
    file: string;
    error: string;
  }[];
  error?: string;
};

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
const [githubUrl, setGithubUrl] = useState("");
const [inputMode, setInputMode] = useState<"zip" | "github">("zip");

const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyzeRepository() {
  if (inputMode === "zip" && !file) return;

  if (inputMode === "github" && !githubUrl.trim()) return;

  setLoading(true);
  setError("");
  setAnalysis(null);

  try {
    const formData = new FormData();

    if (inputMode === "zip" && file) {
      formData.append("repository", file);
    }

    if (inputMode === "github") {
      formData.append("github_url", githubUrl.trim());
    }

    const response = await fetch(
      "http://127.0.0.1:8000/api/analyze",
      {
        method: "POST",
        body: formData,
      }
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);

      throw new Error(
        errorData?.detail ||
          `Backend returned ${response.status}`
      );
    }

    const data = await response.json();

    setAnalysisId(data.analysis_id);
  } catch (err) {
    console.error(err);

    setError(
      err instanceof Error
        ? err.message
        : "Unable to start repository analysis."
    );

    setLoading(false);
  }
}

  /*
   * Poll the backend until the analysis finishes.
   */
  useEffect(() => {
    if (!analysisId) return;

    let cancelled = false;

    const poll = async () => {
      try {
        const response = await fetch(
          `http://127.0.0.1:8000/api/analyze/${analysisId}`
        );

        if (!response.ok) {
          throw new Error(`Status request failed: ${response.status}`);
        }

        const data: Analysis = await response.json();

        if (cancelled) return;

        if (
  data.status === "completed" ||
  data.status === "partial"
) {
  setAnalysis(data);
  setLoading(false);
  return;
}
        if (data.status === "failed") {
          setError(data.error || "Analysis failed.");
          setLoading(false);
          return;
        }

        setTimeout(poll, 800);
      } catch (err) {
        console.error(err);

        if (!cancelled) {
          setError("Unable to retrieve analysis status.");
          setLoading(false);
        }
      }
    };

    poll();

    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  /*
   * -------------------------------------------------------
   * DASHBOARD
   * -------------------------------------------------------
   */

  if (analysis) {
    return (
      <Dashboard
        analysis={analysis}
onReset={() => {
  setAnalysis(null);
  setAnalysisId(null);
  setFile(null);
  setGithubUrl("");
  setInputMode("zip");
  setError("");

        }}
      />
    );
  }

  /*
   * -------------------------------------------------------
   * ANALYSIS PROGRESS
   * -------------------------------------------------------
   */

  if (loading && analysisId) {
    return (
      <AnalysisProgress
        fileName={
          inputMode === "github"
            ? githubUrl || "GitHub repository"
            : file?.name || "repository"
        }
        analysisId={analysisId}
      />
    );
  }

  /*
   * -------------------------------------------------------
   * LANDING PAGE
   * -------------------------------------------------------
   */

  return (
    <main className="min-h-screen bg-[#07090d] text-white">

      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-1/2 top-[-300px] h-[600px] w-[900px] -translate-x-1/2 rounded-full bg-red-500/10 blur-[140px]" />
      </div>

      <nav className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-6">

        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10">
            <span className="text-sm font-bold text-red-400">
              TL
            </span>
          </div>

          <span className="text-lg font-semibold tracking-tight">
            TraceLens
          </span>
        </div>

        <div className="rounded-full border border-white/10 bg-white/[0.03] px-4 py-2 text-xs text-gray-400">
          Security Risk Intelligence
        </div>

      </nav>

      <section className="relative z-10 mx-auto flex max-w-5xl flex-col items-center px-6 pb-24 pt-24 text-center">

        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-red-500/20 bg-red-500/5 px-4 py-2 text-xs text-red-300">
          <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
          Context-aware security analysis
        </div>

        <h1 className="max-w-4xl text-5xl font-semibold leading-tight tracking-tight md:text-7xl">
          Security findings
          <br />
          <span className="text-gray-500">
            aren&apos;t equal.
          </span>
        </h1>

        <p className="mt-7 max-w-2xl text-lg leading-8 text-gray-400">
          TraceLens connects security findings to your
          application&apos;s environment, exposure and
          reachability to show what matters first.
        </p>

        <div className="mt-12 w-full max-w-2xl rounded-2xl border border-white/10 bg-white/[0.03] p-3 shadow-2xl shadow-black/40">

  {/* INPUT MODE */}

  <div className="mb-3 grid grid-cols-2 gap-2 rounded-xl bg-black/30 p-1">

    <button
      type="button"
      onClick={() => {
        setInputMode("zip");
        setGithubUrl("");
        setError("");
      }}
      className={`rounded-lg px-4 py-2.5 text-xs font-medium transition ${
        inputMode === "zip"
          ? "bg-white text-black"
          : "text-gray-500 hover:text-white"
      }`}
    >
      Upload ZIP
    </button>

    <button
      type="button"
      onClick={() => {
        setInputMode("github");
        setFile(null);
        setError("");
      }}
      className={`rounded-lg px-4 py-2.5 text-xs font-medium transition ${
        inputMode === "github"
          ? "bg-white text-black"
          : "text-gray-500 hover:text-white"
      }`}
    >
      GitHub URL
    </button>

  </div>


  {/* ZIP INPUT */}

  {inputMode === "zip" && (
    <label
      htmlFor="repository"
      className="flex min-h-40 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-white/15 bg-black/20 px-6 transition hover:border-red-500/40 hover:bg-red-500/[0.03]"
    >

      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-gray-300">
        ↑
      </div>

      <span className="text-sm font-medium">
        {file
          ? file.name
          : "Drop your repository ZIP here"}
      </span>

      <span className="mt-2 text-xs text-gray-500">
        or click to browse
      </span>

      <input
        id="repository"
        type="file"
        accept=".zip"
        className="hidden"
        onChange={(event) => {
          const selected =
            event.target.files?.[0] ?? null;

          setFile(selected);
          setError("");
        }}
      />

    </label>
  )}


  {/* GITHUB INPUT */}

  {inputMode === "github" && (
    <div className="rounded-xl border border-dashed border-white/15 bg-black/20 p-5">

      <div className="mb-4 text-center">

        <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-sm font-semibold text-gray-300">
          GH
        </div>

        <p className="text-sm font-medium">
          Analyze a public GitHub repository
        </p>

        <p className="mt-2 text-xs text-gray-500">
          Paste the repository URL below
        </p>

      </div>

      <input
        type="url"
        value={githubUrl}
        onChange={(event) => {
          setGithubUrl(event.target.value);
          setError("");
        }}
        placeholder="https://github.com/user/repository"
        className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none transition placeholder:text-gray-700 focus:border-red-500/40"
      />

    </div>
  )}


  {/* ANALYZE */}

  <button
    onClick={analyzeRepository}
    disabled={
      loading ||
      (inputMode === "zip" && !file) ||
      (inputMode === "github" && !githubUrl.trim())
    }
    className="mt-3 w-full rounded-xl bg-white px-5 py-3.5 text-sm font-semibold text-black transition hover:bg-gray-200 disabled:cursor-not-allowed disabled:opacity-30"
  >
    Analyze repository
  </button>

</div>

      

        {error && (
          <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/5 px-5 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="mt-10 flex flex-wrap justify-center gap-3">
          {[
            "Context-aware",
            "Reachability",
            "Risk prioritization",
            "AI-assisted",
          ].map((item) => (
            <div
              key={item}
              className="rounded-full border border-white/10 bg-white/[0.03] px-4 py-2 text-xs text-gray-400"
            >
              {item}
            </div>
          ))}
        </div>

      </section>

      <section className="relative z-10 mx-auto max-w-6xl px-6 pb-24">

        <div className="grid gap-5 md:grid-cols-3">

          <Feature
            number="01"
            title="Detect"
            description="Find security issues across application code, configuration, containers and CI/CD."
          />

          <Feature
            number="02"
            title="Trace"
            description="Connect findings to application structure, exposure and reachable application paths."
          />

          <Feature
            number="03"
            title="Prioritize"
            description="Turn raw findings into contextual risk so developers know what deserves attention first."
          />

        </div>

      </section>

      <footer className="relative z-10 border-t border-white/5 px-6 py-8 text-center text-xs text-gray-600">
        TraceLens AI · Context-aware security risk intelligence
      </footer>

    </main>
  );
}


/* =========================================================
   ANALYSIS PROGRESS
   ========================================================= */

function AnalysisProgress({
  fileName,
  analysisId,
}: {
  fileName: string;
  analysisId: string;
}) {
  const steps = [
    "Repository loaded",
    "Files discovered",
    "Security rules executed",
    "Application structure mapped",
    "Risk paths calculated",
    "Preparing risk intelligence",
  ];

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#07090d] px-6 text-white">

      <div className="w-full max-w-2xl">

        <div className="mb-10 text-center">

          <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10 text-red-400">
            TL
          </div>

          <h1 className="text-3xl font-semibold">
            Analyzing repository
          </h1>

          <p className="mt-2 text-sm text-gray-500">
            {fileName}
          </p>

        </div>

        <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-7">

          <div className="mb-8 flex items-center justify-between">

            <span className="text-sm text-gray-400">
              TraceLens analysis
            </span>

            <span className="font-mono text-xs text-gray-600">
              {analysisId}
            </span>

          </div>

          <div className="space-y-5">

            {steps.map((step, index) => (
              <div
                key={step}
                className="flex items-center gap-4"
              >

                <div
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-xs ${
                    index < 5
                      ? "border-green-500/30 bg-green-500/10 text-green-400"
                      : "border-red-500/30 bg-red-500/10 text-red-400"
                  }`}
                >
                  {index < 5 ? "✓" : "•"}
                </div>

                <span
                  className={
                    index < 5
                      ? "text-sm text-gray-300"
                      : "text-sm text-white"
                  }
                >
                  {step}
                </span>

              </div>
            ))}

          </div>

          <div className="mt-9">

            <div className="mb-2 flex justify-between text-xs">
              <span className="text-gray-500">
                Processing
              </span>

              <span className="text-gray-300">
                Live
              </span>
            </div>

            <div className="h-1.5 overflow-hidden rounded-full bg-white/5">

              <div className="h-full w-4/5 animate-pulse rounded-full bg-red-500" />

            </div>

          </div>

        </div>

        <p className="mt-5 text-center text-xs text-gray-600">
          Repository code is analyzed as data and is never executed.
        </p>

      </div>

    </main>
  );
}


/* =========================================================
   DASHBOARD
   ========================================================= */

function Dashboard({
  analysis,
  onReset,
}: {
  analysis: Analysis;
  onReset: () => void;
}) {
  const [selectedFinding, setSelectedFinding] =
  useState<Finding | null>(null);
  const comparison = useMemo(() => {
  const credentialFindings = analysis.findings.filter(
    (finding) => finding.rule_id === "SEC-001"
  );

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
      "http://127.0.0.1:8000/api/ai/explain",
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
    (f) => f.rule_id === topFinding?.rule_id
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

        <div className="mb-8">

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


        {/* TOP METRICS */}

        <div className="grid gap-4 md:grid-cols-4">

          <MetricCard
            label="Context Risk"
            value={analysis.overall_score.toString()}
            sublabel={analysis.risk_level}
            emphasis
          />

          <MetricCard
            label="Critical"
            value={critical.toString()}
            sublabel="Immediate attention"
          />

          <MetricCard
            label="High"
            value={high.toString()}
            sublabel="Significant risk"
          />

          <MetricCard
            label="Other findings"
            value={(medium + low).toString()}
            sublabel={`${medium} medium · ${low} low`}
          />

        </div>


        {/* MAIN CONTENT */}

        <div className="mt-6 grid gap-6 lg:grid-cols-[1.4fr_0.8fr]">

          {/* PRIORITY */}

          <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-6">

            <div className="mb-6 flex items-center justify-between">

              <div>
                <p className="text-xs uppercase tracking-[0.15em] text-gray-600">
                  Top priority
                </p>

                <h2 className="mt-1 text-xl font-medium">
                  What matters first?
                </h2>
              </div>

              <span className="rounded-full border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs text-red-300">
                Context ranked
              </span>

            </div>


            {topFinding && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/[0.04] p-5">

                <div className="flex items-start justify-between gap-5">

                  <div>

                    <div className="flex items-center gap-2">

                      <span className="h-2 w-2 rounded-full bg-red-400" />

                      <span className="text-xs font-medium uppercase tracking-wider text-red-300">
                        {topFinding.risk_level}
                      </span>

                    </div>

                    <h3 className="mt-3 text-xl font-medium">
                      {topFinding.title}
                    </h3>

                    <p className="mt-2 font-mono text-xs text-gray-500">
                      {topFinding.file}:{topFinding.line}
                    </p>

                  </div>

                  <div className="text-right">

                    <div className="text-4xl font-semibold text-red-400">
                      {topFinding.context_score}
                    </div>

                    <div className="text-xs text-gray-600">
                      Context Risk
                    </div>

                  </div>

                </div>


                {/* CONTEXT */}

                <div className="mt-6 grid grid-cols-3 gap-3">

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


                {/* RISK PATH */}

                {topFinding.risk_path.length > 0 && (
                  <div className="mt-6">

                    <p className="mb-3 text-xs uppercase tracking-wider text-gray-600">
                      Static risk path
                    </p>

                    <div className="rounded-xl border border-white/5 bg-black/30 p-4">

                      {topFinding.risk_path.map(
                        (node, index) => (
                          <div key={`${node}-${index}`}>

                            <div className="font-mono text-xs text-gray-300">
                              {node
                                .replace("file:", "")
                                .replace("route:", "")}
                            </div>

                            {index <
                              topFinding.risk_path.length -
                                1 && (
                              <div className="py-1 text-gray-700">
                                ↓
                              </div>
                            )}

                          </div>
                        )
                      )}

                    </div>

                  </div>
                )}

              </div>
            )}

          </section>


          {/* RISK DELTA */}

          <section className="rounded-2xl border border-white/10 bg-white/[0.025] p-6">

            <p className="text-xs uppercase tracking-[0.15em] text-gray-600">
              TraceLens insight
            </p>

            <h2 className="mt-1 text-xl font-medium">
              Context changes priority
            </h2>

            <p className="mt-3 text-sm leading-6 text-gray-500">
              The same class of security finding can have
              very different importance depending on where
              it exists in the application.
            </p>


            {topFinding && lowestSameRule && (
              <div className="mt-6">

                <div className="rounded-xl border border-white/10 bg-black/20 p-4">

                  <div className="flex items-center justify-between">

                    <span className="text-xs text-gray-500">
                      Highest contextual risk
                    </span>

                    <span className="font-mono text-xl text-red-400">
                      {topFinding.context_score}
                    </span>

                  </div>

                  <div className="mt-3 text-sm">
                    {topFinding.environment} ·{" "}
                    {topFinding.exposure} ·{" "}
                    {topFinding.reachability}
                  </div>

                </div>


                <div className="py-3 text-center text-gray-700">
                  ↓
                </div>


                <div className="rounded-xl border border-white/10 bg-black/20 p-4">

                  <div className="flex items-center justify-between">

                    <span className="text-xs text-gray-500">
                      Lowest same-rule risk
                    </span>

                    <span className="font-mono text-xl text-gray-400">
                      {lowestSameRule.context_score}
                    </span>

                  </div>

                  <div className="mt-3 text-sm text-gray-400">
                    {lowestSameRule.environment} ·{" "}
                    {lowestSameRule.exposure} ·{" "}
                    {lowestSameRule.reachability}
                  </div>

                </div>


                <div className="mt-5 rounded-xl border border-red-500/20 bg-red-500/5 p-4">

                  <div className="flex items-end justify-between">

                    <div>
                      <button
  type="button"
  onClick={() => setShowRiskBreakdown(true)}
  className="mt-4 w-full rounded-xl border border-red-500/20 bg-red-500/[0.035] p-4 text-left transition hover:border-red-500/40 hover:bg-red-500/[0.06]"
>
  <div className="flex items-end justify-between">

    <div>
      <p className="text-xs text-gray-500">
        Context Risk Delta
      </p>

      <p className="mt-1 text-3xl font-semibold text-red-400">
        +{riskDelta}
      </p>
    </div>

    <span className="rounded-md border border-white/10 px-2 py-1 text-[9px] text-gray-600">
      Why?
    </span>

  </div>

  <p className="mt-3 text-xs leading-5 text-gray-500">
    Application context changed the priority
    of the same finding class by {riskDelta} points.
  </p>

  <p className="mt-3 text-[9px] uppercase tracking-wider text-gray-700">
    Click to inspect the context change →
  </p>

</button>
                    </div>

                    <span className="text-xs text-gray-600">
                      points
                    </span>

                  </div>

                  <p className="mt-3 text-xs leading-5 text-gray-500">
                    Application context changed the priority
                    of the same finding class by {riskDelta}{" "}
                    points.
                  </p>

                </div>

              </div>
            )}

          </section>

        </div>

        {/* WHY FIRST */}

        {topFinding && (
          <section className="mt-6 rounded-2xl border border-white/10 bg-white/[0.025] p-6">

            <div className="flex items-start gap-4">

              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-red-500/20 bg-red-500/10 text-red-400">
                !
              </div>

              <div>

                <p className="text-xs uppercase tracking-wider text-gray-600">
                  Why fix this first?
                </p>

                <h2 className="mt-1 text-lg font-medium">
                  {topFinding.title}
                </h2>

                <p className="mt-3 max-w-3xl text-sm leading-6 text-gray-400">
                  This finding is prioritized because it is
                  associated with{" "}
                  <strong className="text-gray-200">
                    {topFinding.environment}
                  </strong>{" "}
                  context,{" "}
                  <strong className="text-gray-200">
                    {topFinding.exposure.toLowerCase()}
                  </strong>{" "}
                  exposure and{" "}
                  <strong className="text-gray-200">
                    {topFinding.reachability.toLowerCase()}
                  </strong>{" "}
                  static reachability.
                </p>

                <p className="mt-2 max-w-3xl text-xs leading-5 text-gray-600">
                  TraceLens uses repository evidence and
                  static application relationships to
                  estimate contextual risk. This is not a
                  proof of runtime exploitability.
                </p>

              </div>

            </div>

          </section>
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

function FindingInspector({
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
                  platform's encrypted secret mechanism instead.
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
function RiskComparison({
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

/* =========================================================
   SMALL COMPONENTS
   ========================================================= */

function MetricCard({
  label,
  value,
  sublabel,
  emphasis = false,
}: {
  label: string;
  value: string;
  sublabel: string;
  emphasis?: boolean;
}) {
  return (
    <div
      className={`rounded-2xl border p-5 ${
        emphasis
          ? "border-red-500/20 bg-red-500/[0.04]"
          : "border-white/10 bg-white/[0.025]"
      }`}
    >

      <p className="text-xs uppercase tracking-wider text-gray-600">
        {label}
      </p>

      <div
        className={`mt-3 text-4xl font-semibold ${
          emphasis
            ? "text-red-400"
            : "text-white"
        }`}
      >
        {value}
      </div>

      <p className="mt-1 text-xs text-gray-600">
        {sublabel}
      </p>

    </div>
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
function RiskBreakdownModal({
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

function Feature({
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