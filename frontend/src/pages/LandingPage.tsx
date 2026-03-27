import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AppFrame } from "../components/AppFrame";

import { API_BASE } from "../lib/apiConfig";

type Feature = {
  title: string;
  description: string;
};

const features: Feature[] = [
  {
    title: "Structured Workflow",
    description:
      "Move from setup to result with a clear stage-by-stage experience and consistent controls.",
  },
  {
    title: "Integrated Scanning",
    description:
      "Backend checks, Slither output, and LLM reasoning are connected in one continuous flow.",
  },
  {
    title: "Evidence Ready",
    description:
      "Final findings include extracted evidence, snippets, and reporting actions for review.",
  },
];

function HeroSection() {
  const [backendStatus, setBackendStatus] = useState<
    "checking" | "online" | "offline"
  >("checking");

  useEffect(() => {
    let cancelled = false;

    const checkBackend = async () => {
      try {
        const res = await fetch(`${API_BASE}/healthz`);
        if (!cancelled) {
          setBackendStatus(res.ok ? "online" : "offline");
        }
      } catch {
        if (!cancelled) {
          setBackendStatus("offline");
        }
      }
    };

    checkBackend();

    return () => {
      cancelled = true;
    };
  }, []);

  const statusLabel =
    backendStatus === "checking"
      ? "Checking backend..."
      : backendStatus === "online"
        ? "Backend connected"
        : "Backend offline";

  const statusClass =
    backendStatus === "online"
      ? "border-emerald-300 bg-emerald-100 text-emerald-700"
      : backendStatus === "offline"
        ? "border-rose-300 bg-rose-100 text-rose-700"
        : "border-slate-300 bg-slate-100 text-slate-700";

  return (
    <section className="aw-card">
      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr] lg:items-center">
        <div>
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-slate-500">
            Smart Contract Audit Workspace
          </p>
          <h1 className="aw-title text-3xl font-bold leading-tight text-[#1E293B] md:text-4xl">
            Home Page aligned with the Audit Page visual system.
          </h1>
          <p className="aw-subtle mt-3 max-w-2xl text-sm md:text-base">
            Same gradients, same cards, same controls. Use this page to check
            system readiness and jump directly into the audit workflow.
          </p>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span
              className={`rounded-full border px-3 py-1 text-xs font-medium ${statusClass}`}
            >
              {statusLabel}
            </span>
            <span className="aw-chip">Frontend: Online</span>
            <span className="aw-chip">Pipeline: Phase2</span>
          </div>

          <div className="mt-5 flex flex-wrap gap-3">
            <Link to="/audit" className="aw-button w-auto px-5 py-2">
              Open Audit Page
            </Link>
            <a
              href="#features"
              className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-[#1E293B] transition hover:bg-slate-50"
            >
              View Capabilities
            </a>
          </div>
        </div>

        <aside className="rounded-xl border border-slate-200 bg-slate-50 p-4">
          <h2 className="aw-title text-base font-semibold text-[#1E293B]">
            Workflow Snapshot
          </h2>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4 lg:grid-cols-2">
            <div className="aw-step aw-step-active">1. Audit Created</div>
            <div className="aw-step">2. Slither Scan</div>
            <div className="aw-step">3. LLM Analysis</div>
            <div className="aw-step">4. Final Report</div>
          </div>
          <p className="aw-subtle mt-3 text-xs">
            This home panel mirrors the same stage language used in the audit
            page.
          </p>
        </aside>
      </div>
    </section>
  );
}

function FeaturesSection() {
  return (
    <section id="features" className="aw-card">
      <div className="flex items-center justify-between gap-3">
        <h2 className="aw-title text-2xl font-semibold text-[#1E293B]">
          Capabilities
        </h2>
        <span className="aw-chip aw-chip-accent">Shared UI Language</span>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-3">
        {features.map((feature) => (
          <article
            key={feature.title}
            className="rounded-lg border border-slate-200 bg-white p-4 transition hover:-translate-y-0.5 hover:border-slate-400"
          >
            <h3 className="text-base font-semibold text-[#1E293B]">
              {feature.title}
            </h3>
            <p className="aw-subtle mt-2 text-sm leading-6">
              {feature.description}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer id="footer" className="aw-card py-4">
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <p className="aw-subtle">© 2026 MinimalSite</p>
        <p className="aw-subtle">
          Integrated with FastAPI backend and audit pipeline
        </p>
      </div>
    </footer>
  );
}

export function LandingPage() {
  return (
    <AppFrame>
      <HeroSection />
      <FeaturesSection />
      <Footer />
    </AppFrame>
  );
}
