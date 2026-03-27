import { useState } from "react";
import type { ReactNode } from "react";

import { AppSidebar } from "./AppSidebar";

interface AppFrameProps {
  children: ReactNode;
}

export function AppFrame({ children }: AppFrameProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <main className="min-h-screen bg-app-gradient py-6 pr-4 text-[#1E293B]">
      <div className="aw-app-layout">
        {!sidebarCollapsed ? (
          <AppSidebar onCollapse={() => setSidebarCollapsed(true)} />
        ) : (
          <button
            type="button"
            className="aw-sidebar-reopen"
            onClick={() => setSidebarCollapsed(false)}
            title="Open menu"
            aria-label="Open menu"
          >
            -&gt;
          </button>
        )}

        <div
          className={`aw-app-content ${
            sidebarCollapsed ? "aw-app-content-expanded" : ""
          }`}
        >
          <div className="aw-shell space-y-4">{children}</div>
        </div>
      </div>
    </main>
  );
}
