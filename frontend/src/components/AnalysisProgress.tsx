"use client";

export default function AnalysisProgress({
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
