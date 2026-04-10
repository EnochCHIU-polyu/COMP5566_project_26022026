import { Link } from "react-router-dom";

type NavPage = "home" | "audit";

interface AppNavbarProps {
  current: NavPage;
  showAnchors?: boolean;
}

function navClass(active: boolean): string {
  if (active) {
    return "rounded-md border px-3 py-1.5 text-sm aw-chip-accent";
  }
  return "rounded-md border border-slate-300 px-3 py-1.5 text-sm text-[#1E293B] transition hover:bg-slate-50";
}

export function AppNavbar({ current, showAnchors = false }: AppNavbarProps) {
  return (
    <header className="aw-card backdrop-blur">
      <nav className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <Link
          to="/"
          className="text-lg font-semibold tracking-tight text-[#1E293B]"
        >
          MinimalSite
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <Link to="/" className={navClass(current === "home")}>
            Home
          </Link>
          <Link to="/audit" className={navClass(current === "audit")}>
            Audit
          </Link>
          {showAnchors && (
            <>
              <a
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-[#1E293B] transition hover:bg-slate-50"
                href="#features"
              >
                Capabilities
              </a>
              <a
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm text-[#1E293B] transition hover:bg-slate-50"
                href="#footer"
              >
                Contact
              </a>
            </>
          )}
        </div>
      </nav>
    </header>
  );
}
