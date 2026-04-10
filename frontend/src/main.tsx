import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { AuditPage } from "./pages/AuditPage";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { EndPage } from "./pages/EndPage";
import { LandingPage } from "./pages/LandingPage";
import { NewVulnerabilityPage } from "./pages/NewVulnerabilityPage";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/benchmark" element={<BenchmarkPage />} />
        <Route path="/new-vulnerability" element={<NewVulnerabilityPage />} />
        <Route path="/evaluation" element={<EndPage />} />
        <Route
          path="/more (wip)"
          element={<Navigate to="/evaluation" replace />}
        />
        <Route path="/end" element={<Navigate to="/evaluation" replace />} />
        <Route path="/function" element={<Navigate to="/audit" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
