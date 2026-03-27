# Frontend (React + TypeScript + Vite)

This folder contains the web client for smart-contract audit workflows.

## Tech Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
- React Router
- Zustand (audit state)

## Folder Structure

```text
frontend/
├── src/
│   ├── main.tsx                         # App entry + route registration
│   ├── styles.css                       # Global design tokens and app styles
│   ├── components/
│   │   ├── AppFrame.tsx                 # Shared layout shell
│   │   ├── AppNavbar.tsx                # Top navigation component
│   │   └── AppSidebar.tsx               # Sidebar navigation component
│   ├── pages/
│   │   ├── LandingPage.tsx              # Home page
│   │   ├── AuditPage.tsx                # Main audit workflow page
│   │   ├── BenchmarkPage.tsx            # Benchmark workflow page
│   │   ├── NewVulnerabilityPage.tsx     # Vulnerability submission form
│   │   └── EndPage.tsx                  # Placeholder page
│   ├── features/
│   │   ├── audit/
│   │   │   ├── components/              # Audit UI panels
│   │   │   ├── hooks/useAuditStream.ts  # SSE stream lifecycle
│   │   │   ├── services/auditApi.ts     # Audit API client
│   │   │   └── store/auditStore.ts      # Zustand store
│   │   ├── benchmark/
│   │   │   └── services/benchmarkApi.ts # Benchmark API client
│   │   └── vulnerabilities/
│   │       └── services/vulnerabilityApi.ts # Vulnerability submit API
│   └── lib/
│       └── apiConfig.ts                 # API base URL config
├── package.json
└── vite.config.ts
```

## Routes

Defined in `src/main.tsx`:

- `/` -> landing page
- `/audit` -> audit workflow
- `/benchmark` -> benchmark workflow
- `/new-vulnerability` -> submit vulnerability

## Environment

The frontend reads API base URL from:

- `VITE_API_URL`

Fallback value is `http://localhost:8000` if not provided.

## Commands

From the `frontend/` folder:

```bash
npm install
npm run dev
npm run build
npm run preview
```

## API Integration Notes

- Audit page uses SSE endpoint to stream audit events in near-real-time.
- Benchmark page supports dataset load, benchmark run, and LLM connectivity checks.
- New Vulnerability page posts to backend endpoint:
  - `POST /api/v1/vulnerabilities/submissions`

## Troubleshooting

- If requests fail with network errors:
  - Ensure backend is running on the same host/port as `VITE_API_URL`.
- If you see CORS issues:
  - Verify backend CORS settings in `backend/app/main.py`.
- If TypeScript build fails:
  - Run `npm run build` to surface exact diagnostics.
