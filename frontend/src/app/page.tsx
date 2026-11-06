"use client";

import AnalysisProgress from "../components/AnalysisProgress";
import Dashboard, { Feature } from "../components/Dashboard";
import { API_BASE_URL } from "../lib/api";
import type { Analysis } from "../types";

import { useEffect, useState } from "react";

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
      `${API_BASE_URL}/api/analyze`,
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
          `${API_BASE_URL}/api/analyze/${analysisId}`
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