import { Link } from "react-router-dom";
import { AppFrame } from "../components/AppFrame";

export function LandingPage() {
  return (
    <AppFrame>
      <section className="mx-auto flex min-h-[70vh] w-full max-w-3xl items-center justify-center">
        <div className="aw-card w-full text-center">
          <p className="aw-subtle text-xs uppercase tracking-[0.2em]">
            Smart Contract Security
          </p>
          <h1 className="aw-title mt-3 text-3xl font-bold md:text-4xl">
            Start page
          </h1>
          <p className="aw-subtle mx-auto mt-3 max-w-xl text-sm md:text-base">
            Click start to open the audit page.
          </p>

          <div className="mt-7 flex justify-center">
            <Link to="/audit" className="aw-button w-auto px-8 py-3 text-base">
              Start Audit
            </Link>
          </div>
        </div>
      </section>
    </AppFrame>
  );
}
