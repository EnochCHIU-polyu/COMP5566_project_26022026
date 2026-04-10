import { NavLink } from "react-router-dom";

const navItems = [
  { to: "/", label: "Home Page" },
  { to: "/audit", label: "Audit" },
  { to: "/benchmark", label: "Benchmark" },
  { to: "/new-vulnerability", label: "New Vulnerability" },
  { to: "/evaluation", label: "Evaluation" },
];

function linkClass(active: boolean): string {
  if (active) {
    return "aw-side-link aw-side-link-active";
  }
  return "aw-side-link";
}

interface AppSidebarProps {
  onCollapse: () => void;
}

export function AppSidebar({ onCollapse }: AppSidebarProps) {
  return (
    <aside className="aw-card aw-sidebar backdrop-blur">
      <div className="flex items-start justify-between gap-2 border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-[#1E293B]">
            ContractSite
          </h1>
          <p className="aw-subtle mt-1 text-xs">Smart Contract Security UI</p>
        </div>
        <button
          type="button"
          className="rounded-md border border-slate-300 px-2 py-1 text-sm text-[#1E293B] transition hover:bg-slate-50"
          onClick={onCollapse}
          title="Hide menu"
          aria-label="Hide menu"
        >
          ☰
        </button>
      </div>

      <nav className="mt-4 flex flex-col gap-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) => linkClass(isActive)}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
