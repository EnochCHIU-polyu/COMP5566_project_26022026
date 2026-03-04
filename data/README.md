# Data Directory

This directory stores all datasets used by the framework.

---

## Structure

```
data/
├── benchmarks/
│   ├── smartbugs/     # SmartBugs Curated benchmark (cloned from GitHub)
│   └── solidifi/      # SolidiFI injected-bug benchmark (cloned from GitHub)
├── vulnerable_contracts/   # Known-vulnerable .sol / .json files
└── synthetic_contracts/    # Auto-generated synthetic contracts (created at runtime)
```

---

## Setup: Download Benchmark Datasets

Both datasets are registered as **git submodules**. After cloning the outer repository, initialise them with:

```bash
git submodule update --init --recursive
```

After that, verify the datasets load correctly:

```bash
python main.py download-benchmarks --dataset all
```

If you need to add the submodules manually (e.g. in a fresh checkout without the `.gitmodules` file):

```bash
git submodule add https://github.com/smartbugs/smartbugs-curated.git data/benchmarks/smartbugs
git submodule add https://github.com/smartbugs/SolidiFI-benchmark data/benchmarks/solidifi
```

---

## Synthetic Contracts

Synthetic contracts are generated at runtime via:

```bash
python main.py generate-synthetic --num-vulns 2
```

Output is saved to `data/synthetic_contracts/`.

---

## Notes

- `data/benchmarks/` is excluded from version control (listed in `.gitignore`).
- Parsed datasets are cached as `contracts.json` inside each benchmark subdirectory to avoid re-parsing on subsequent runs.
