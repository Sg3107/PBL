# NeuralCC — Intelligent Multi-Agent Compiler & Security Hardening Studio

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![C Standard: ISO C11](https://img.shields.io/badge/Standard-ISO%20C11-green.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Multi-Lang: C | C++ | Java | Python](https://img.shields.io/badge/Frontends-C%20%7C%20C%2B%2B%20%7C%20Java%20%7C%20Python-orange.svg)](#multi-language-support)
[![Security: CWE Top 25 & OWASP LLM](https://img.shields.io/badge/Security-CWE%20Top%2025%20%7C%20OWASP%20LLM-red.svg)](#autonomous-security-hardening-engine)
[![Offline: 100% Client-Side](https://img.shields.io/badge/Runtime-100%25%20Offline%20Browser-purple.svg)](#in-browser-virtual-runtime)

> **NeuralCC** is a next-generation agentic compiler and security hardening studio. It combines classical compiler architecture (Lexing, AST Parsing, Semantic Scope Analysis, CFG Construction, Dead Code Elimination) with an autonomous **Multi-Agent Orchestration Pipeline**, an in-browser **Virtual C Runtime Engine**, and an **Adversarial AI (AAI) Security Shield**.

---

## 🌟 Key Features

### 1. 🤖 8-Stage Multi-Agent Compiler Pipeline
Unlike monolithic compilers that emit cryptic errors and abort, NeuralCC orchestrates **8 specialized cooperative agents**:
1. **HeaderGuardAgent**: Validates preprocessor directives, auto-resolves header typos, and injects missing standard headers (`<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<conio.h>`).
2. **BoilerplateAuditorAgent**: Enforces ISO C compliance, detects entry-point typos (`void mian()` $\to$ `int main(void)`), and repairs return conventions.
3. **LexiScanAgent**: Lexical analysis, stray token detection, unclosed string/char literals, and multi-line comment termination.
4. **GrammarGuardAgent**: AST construction, control-structure parenthesis balancing, and intra-line semicolon repair.
5. **SemScopeAgent**: Semantic symbol tables, type checking, duplicate declaration isolation, and undeclared variable ingestion.
6. **OptiGenAgent**: Intermediate Representation (IR 3-Address Code generation), Control Flow Graph (CFG) construction, and Dead Code Elimination (DCE).
7. **SecurAuditAgent**: Deep static security auditing for memory safety (CWE Top 25) and injection vulnerabilities.
8. **AutoFixAgent**: Autonomous code synthesis that rewrites defective code into 100% bug-free, hardened C.

---

### 2. 🛡️ Autonomous Security Hardening Engine
NeuralCC detects, blocks, and auto-hardens critical system vulnerabilities:
- **CWE-120 (Buffer Overflow / Stack Smashing)**: Replaces unbounded `gets()`, `strcpy()`, and `scanf("%s")` with size-bounded `fgets()`, `strncpy()`, and field-bounded `scanf("%63s")` with guaranteed `\0` null-terminators.
- **CWE-134 (Format String Injection)**: Hardens `printf(variable)` $\to$ `printf("%s", variable)` and bounds `sprintf` $\to$ `snprintf`.
- **CWE-416 (Use-After-Free)**: Detects dangling pointers dereferenced after `free()` and auto-zeroes them (`ptr = NULL;`).
- **CWE-476 (NULL Pointer Dereference)**: Injects defensive allocation guard clauses: `if (ptr == NULL) { ... }`.
- **CWE-401 (Memory Leaks)**: Automatically injects safe heap deallocations before function return points.
- **CWE-190 (Integer Wraparound Overflow)**: Detects unchecked fixed-width arithmetic and injects range boundary checks.
- **CWE-367 (TOCTOU Race Conditions)**: Flags check-then-use file race conditions (`access()` followed by `fopen()`).
- **CWE-338 & CWE-327 (Weak PRNG & Broken Crypto)**: Detects predictable `rand()` token generation and broken ciphers (MD5, DES).
- **CWE-798 (Hard-Coded Credentials)**: Scans for embedded plaintext API keys and credentials.
- **CWE-78 (Taint Analysis)**: Traces untrusted user inputs flowing directly into command shell execution sinks (`system()`).

---

### 3. 🛡️⚡ AAI Shield Agent (Adversarial AI Sentinel)
Conforming to **OWASP Top 10 for LLM/Agents** and **MITRE ATLAS**:
- **Prompt Injection Defense (OWASP-LLM01 / CWE-20)**: Neutralizes malicious instructions in comments trying to override compiler policies.
- **System Policy Guard (OWASP-LLM07 / CWE-693)**: Prevents adversarial evasion of safety filters.
- **Trojan Backdoor Detection (OWASP-LLM05 / CWE-506)**: Ensures automated code healing never injects covert backdoors or reverse shells.
- **Data Exfiltration Guard (OWASP-LLM02 / CWE-200)**: Detects covert channel socket transmissions or credential harvesting.

---

### 4. 🏛️ 15 Diverse Enterprise Quick-Test Codebases
Every test preset loads a completely unique, multi-module industrial application (500–1,000+ lines each):
1. **0. Header Faults**: 🏦 *Enterprise Core Banking & ATM Transaction Ledger* (514 lines)
2. **0.5. Boilerplate**: ✈️ *Commercial Aviation Flight Radar & Scheduling* (513 lines)
3. **⚡ All-in-One Multi-Fault**: 🏥 *Hospital Intensive Care (ICU) Telemetry* (512 lines)
4. **1. Missing Semicolon**: 📦 *Global Supply Chain & Warehouse Inventory* (514 lines)
5. **1.5. Missing Equal**: ⚡ *Smart Power Grid & Renewable Energy Load Balancer* (514 lines)
6. **2. Unmatched { }**: 🚦 *Metropolitan Smart City Traffic Signal Command Center* (513 lines)
7. **3. Undeclared Var**: 📈 *Quantitative Portfolio & Algorithmic Trading Desk* (514 lines)
8. **🚨 4. CWE-120 (gets)**: 🛡️ *Deep Packet Inspection Network Firewall* (515 lines)
9. **5. Hacker Exploit**: 🔐 *Biometric Defense Vault Security Gateway* (516 lines)
10. **6. CWE-134 (printf)**: ☁️ *Distributed Cloud Microservices Syslog Daemon* (517 lines)
11. **7. CWE-401 (Leak)**: 🤖 *Autonomous Robotics LiDAR 3D Spatial Mapping Engine* (515 lines)
12. **7.5. CWE-416 (Heap UAF)**: 🧠 *Kernel Slab Memory & Free-List Allocator* (516 lines)
13. **7.8. CWE-190 (Wrap)**: 💳 *FinTech High-Frequency Micro-Settlement Clearinghouse* (517 lines)
14. **8. Valid C Code**: 🎓 *University Academic Student Registry* (514 lines)
15. **🏛️ Massive Microkernel**: 🖥️ *Real-Time Monolithic OS Microkernel* (**3,994 lines**)

---

### 5. 🌐 Multi-Language Support
- **C (ISO C11)**: Native lexing, parsing, symbol tables, CFG, IR, Auto-Correct, and virtual runtime.
- **C++ (ISO C++17)**: Class definitions, member access, stream directions (`cout <<`), OOP hierarchy, RAII memory checks.
- **Java (Java 17 SE)**: Class wrappers, entry points, `System.out` casing, command injection auditing (`Runtime.exec`).
- **Python (Python 3.11)**: Indentation tracking, colon validation (`def`/`if`), Python 2 vs 3 syntax, and `eval()` code injection checks.

---

## 🚀 Quick Start

### Option A: In-Browser (100% Zero-Dependency Offline)
Simply double-click `index.html` or open it in any modern browser (Chrome, Edge, Firefox, Safari). All compiler engines run entirely client-side via JavaScript.

### Option B: Local Node.js HTTP Server
```bash
# Clone repository
git clone https://github.com/<your-username>/NeuralCC.git
cd NeuralCC

# Launch server
node server.js
```
Open your browser at `http://localhost:3000`.

---

## 🧪 Comprehensive Test Suites & Verification

NeuralCC includes automated validation suites:

```bash
# Verify all 15 distinct enterprise presets (100% pass target)
node test_verify_all_presets.js

# Run the 105-codebase regression suite
node run_100_codebase_suite.js
```

Benchmark Results:
- **105 / 105** pristine real-world C codebases compile with **0 errors (100%)**.
- **105 / 105** destructively mutated codebases healed to **0 errors (100%)**.
- **3,994-line OS Microkernel**: Compiles in **51 ms** and executes in virtual VM in **2 ms**.

---

## 🔒 Security & Privacy Policy

- **Zero Cloud Leaks**: NeuralCC's core scanner, parser, AST engine, security analyzer, and virtual runtime execute **100% locally in-browser**.
- **Credentials Policy**: No API keys, passwords, or personal credentials are required or committed to this repository. Optional cloud inference uses local `.env` files protected by `.gitignore`.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
