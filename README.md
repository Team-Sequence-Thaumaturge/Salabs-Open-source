# Sequence Autonomic Parsing & QA (SAPQ) Engine

The **Sequence Autonomic Parsing & QA (SAPQ) Engine** is an advanced code integrity auditor designed to detect semantic contradictions, out-of-order execution, and incomplete mockup stubs (anti-mockup gate) in source code. 

It is specifically engineered to audit LLM-generated code and autonomous multi-agent deployments, acting as a structural circuit breaker before live production push.

---

## 🛡️ Core Capabilities

### 1. 4-Directional Interleaved Cross-Parsing
The engine traces program trajectories by running four independent scanning vectors across the code:
- **Phase A (Forward Def)**: Scans declarations (`const`, `let`, `function`, `id="..."` DOM anchors).
- **Phase Z (Backward Ref)**: Scans reference usages (`document.getElementById`, method calls, object property lookups).
- **Phase a (Skip-Forward State)**: Traces mutations and inline events (`onclick`, `onchange`, variable assignments).
- **Phase z (Skip-Backward Event)**: Audits event loop registers (`addEventListener`, `setTimeout`, message listeners).

### 2. Contradiction & Bug Detection
- **`TORSION_CROSSING` (Reverse Dependency)**: Flags when a variable, function, or DOM element is called or referenced in the execution path *before* it has been physically declared or bound.
- **`GHOST_NODE` (Zombie Variable)**: Detects dead/isolated variables that are declared in the forward pass but never read or queried in the backward pass.
- **`CLOSED_LOOP_ANOMALY`**: Identifies circular event triggers or unhandled event loop leaks.

### 3. Anti-Mockup AST Validation (`MOCKUP_HALLUCINATION`)
LLMs often "stub out" complex business logic with mock placeholders. SAPQ audits Python AST structures and Javascript files to detect:
- Hardcoded test returns (`return true;`, `Math.random()`) in crypto, checkout, or network layers.
- Incomplete mock callbacks (`setTimeout` dummy returns instead of actual REST API/WebCrypto bindings).
- Stub comments (`TODO`, `FIXME`, `mock implementation`) in core production features.

### 4. Windows Background Popup Vulnerability Audit
In Windows desktop environments, background scripts spawning subprocesses without proper flags cause flashing CMD prompt windows. SAPQ automatically audits and flags any python `subprocess` or `os.system` calls lacking secure `creationflags` (like `0x08000000` / `CREATE_NO_WINDOW`).

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- `requests` (for the active API prober module)

```bash
pip install requests
```

---

## 💻 CLI Usage

Audit a specific python file or an entire directory:

```bash
# Run directory-wide or file audit via CLI
python -m sapq.sapq_cli "path/to/your/code"
```

Verify a specific script using the multi-vector parser runner:

```bash
python multi_vector_parser.py "path/to/your/file.js"
```

---

## 🎨 Interactive Web Visualizer

If you prefer a visual interface, SAPQ includes a lightweight, 100% client-side HTML5 Canvas cockpit:

1. Open `tools/jules-ai-qa-cross-parsing-auditor.html` in any web browser.
2. Drag & drop or paste your source code into the editor.
3. Click **Run Multi-Vector Audit** to see a live visual graph mapping forward declarations to backward references, highlighting torsion lines, mockups, and dead variables instantly.

---

## 📄 License
Licensed under the **MIT License**. Feel free to use, modify, and distribute for personal or commercial projects.
