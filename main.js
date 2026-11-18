// main.js - NeuralCC Studio Multi-Agent Orchestration

let lastCompile = null;
let lastOrchestration = null;
const agentKeys = ['header', 'boiler', 'lex', 'parse', 'sem', 'ir', 'sec'];

// ════════════════════════════════════════════════════
//  BACKGROUND ANIMATION & UTILS
// ════════════════════════════════════════════════════
(function () {
  const c = document.getElementById('bg-canvas');
  if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, p = [];
  function r() { W = c.width = window.innerWidth; H = c.height = window.innerHeight; }
  window.addEventListener('resize', r); r();
  for (let i = 0; i < 60; i++) p.push({ x: Math.random() * 1e4 % 1, y: Math.random() * 1e4 % 1, vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3, r: Math.random() * 1.5 + .5, l: Math.random() });
  function frame() {
    ctx.clearRect(0, 0, W, H); ctx.strokeStyle = 'rgba(0, 0, 0, 0.03)'; ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 60) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 60) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
    p.forEach(q => {
      q.x += q.vx; q.y += q.vy; if (q.x < 0) q.x = W; if (q.x > W) q.x = 0; if (q.y < 0) q.y = H; if (q.y > H) q.y = 0; q.l += .003;
      ctx.beginPath(); ctx.arc(q.x, q.y, q.r, 0, Math.PI * 2); ctx.fillStyle = `rgba(2, 132, 199, ${.15 + .1 * Math.sin(q.l * 3)})`; ctx.fill();
    });
    requestAnimationFrame(frame);
  }
  frame();
})();

const codeInput = document.getElementById('codeInput');
const lineNums = document.getElementById('lineNums');

function updateLineNums() {
  if (!codeInput || !lineNums) return;
  const n = codeInput.value.split('\n').length;
  lineNums.textContent = Array.from({ length: n }, (_, i) => i + 1).join('\n');
  lineNums.scrollTop = codeInput.scrollTop;
}

if (codeInput && lineNums) {
  codeInput.addEventListener('input', () => {
    updateLineNums();
    // Debounced live sensing trigger after typing pauses
    debounceLiveSensing();
  });
  codeInput.addEventListener('scroll', () => { lineNums.scrollTop = codeInput.scrollTop; });
  codeInput.addEventListener('keydown', e => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const s = codeInput.selectionStart;
      codeInput.value = codeInput.value.substring(0, s) + '    ' + codeInput.value.substring(codeInput.selectionEnd);
      codeInput.selectionStart = codeInput.selectionEnd = s + 4;
      updateLineNums();
    }
  });
}

let liveSensingTimer = null;
function debounceLiveSensing() {
  clearTimeout(liveSensingTimer);
  liveSensingTimer = setTimeout(() => {
    // Perform non-intrusive lightweight compile for live AI sensing
    runLightweightSensing();
  }, 450);
}

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

let currentUserTab = 'sensing';

function switchTab(name, isUserClick = false) {
  if (isUserClick || arguments.length === 1) {
    currentUserTab = name;
  }
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const tc = document.getElementById('tab-' + name);
  const tb = document.getElementById('tab-btn-' + name);
  if (tc) tc.classList.add('active');
  if (tb) tb.classList.add('active');
  if (name === 'aai-shield') {
    setTimeout(initAAILossChartIfNeeded, 50);
  }
  if (name === 'ir' && lastCompile) {
    const activeSymbols = (lastCompile.symbols && lastCompile.symbols.length > 0)
      ? lastCompile.symbols
      : (typeof analyze !== 'undefined' && analyze._lastSymbols) || [];
    renderIR(lastCompile.irInstrs || [], lastCompile.cfgResult || null, lastCompile.secWarnings || []);
    renderSymbols(activeSymbols);
  }
}

const DEFAULT_ENV_GROQ_KEY = '';

// Automatically fetch configuration from server.js .env loader on startup
(async function initEnvConfig() {
  try {
    const res = await fetch('/api/config');
    if (res.ok) {
      const data = await res.json();
      if (data.groqApiKey) {
        sessionStorage.setItem('_ncc_k', data.groqApiKey);
        window._GROQ_API_KEY = data.groqApiKey;
        console.log('[NeuralCC] Successfully loaded Groq API Key from .env');
        return;
      }
    }
  } catch (err) {
    // Offline or direct file:// load
  }
  sessionStorage.setItem('_ncc_k', DEFAULT_ENV_GROQ_KEY);
  window._GROQ_API_KEY = DEFAULT_ENV_GROQ_KEY;
})();

function _getKey() {
  const el = document.getElementById('apiKey');
  const live = el ? el.value.trim() : '';
  return live || sessionStorage.getItem('_ncc_k') || localStorage.getItem('_ncc_k') || window._GROQ_API_KEY || DEFAULT_ENV_GROQ_KEY;
}

// ════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ════════════════════════════════════════════════════
function showToast(msg) {
  let toast = document.getElementById('studioToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'studioToast';
    toast.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#0f172a;color:#fff;padding:12px 20px;border-radius:6px;font-family:"Space Mono",monospace;font-size:0.75rem;box-shadow:0 10px 25px rgba(0,0,0,0.3);z-index:99999;transition:all 0.3s;border-left:4px solid #10b981;display:flex;align-items:center;gap:10px;';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = '1';
  toast.style.transform = 'translateY(0)';
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
  }, 2800);
}

// ════════════════════════════════════════════════════
//  COMPILER & MULTI-AGENT EXECUTION
// ════════════════════════════════════════════════════
async function runCompiler() {
  if (!codeInput) return;
  const source = codeInput.value;
  if (!source.trim()) return;

  const statPhase = document.getElementById('stat-phase');
  if (statPhase) statPhase.textContent = 'ANALYZING...';

  // 0. Pre-Flight Agentic AI Security Inspection (AAISecShield Sentinel)
  let aaiShieldResult = null;
  if (typeof AAISecShield !== 'undefined') {
    aaiShieldResult = AAISecShield.inspectInput(source);
    updateAAIShieldUI(aaiShieldResult);
  }

  const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';

  // Multi-Language Compiler Dispatcher (C++, Java, Python)
  if (currentLang !== 'c' && typeof MultiLangEngine !== 'undefined') {
    const mlResult = MultiLangEngine.compile(source, currentLang);
    if (mlResult) {
      lastCompile = {
        language: currentLang,
        tokens: mlResult.tokens,
        ast: mlResult.ast,
        errors: mlResult.errors,
        secWarnings: mlResult.secWarnings,
        irInstrs: mlResult.irInstrs,
        cfgResult: mlResult.cfgResult,
        source,
        hardenedData: null,
        secReport: mlResult.secReport,
        orchestration: mlResult.orchestration,
        symbols: mlResult.symbols || []
      };
      lastOrchestration = mlResult.orchestration;

      finishCompile(mlResult.tokens, mlResult.errors, mlResult.semanticErrors, mlResult.secWarnings, mlResult.irInstrs, mlResult.cfgResult, mlResult.secReport, mlResult.orchestration, mlResult.symbols);

      if (typeof AgentNetwork !== 'undefined' && AgentNetwork.startNegotiation) {
        AgentNetwork.startNegotiation(source, lastCompile);
      }
      return;
    }
  }

  // 1. Lexical Phase (ISO C)
  const { tokens, errors: lexErrors } = lex(source);
  const vis = tokens.filter(t => t.type !== TT.COMMENT && t.type !== TT.EOF);

  // 2. Preprocessor & Headers Phase (Always runs: checks missing #, typos in headers, missing std headers)
  const { errors: headerErrors, includedHeaders, unusedHeaders } = validatePreprocessorAndHeaders(source, tokens);

  // 3. Syntax / Parser Phase (Always runs: builds AST and catches syntax errors with robust error recovery)
  const pResult = parse(tokens, source, includedHeaders);
  const ast = pResult.ast || { kind: 'Program', children: [] };
  const parseErrors = (pResult.errors || []).filter(e => e.type === 'ParseError');

  // 4. Boilerplate & Structural Validation Phase (Checks main(), void main, return 0, rogue global statements)
  const boilerErrors = validateBoilerplateAndStructure(source, tokens, ast);

  // 5. Semantic Analysis Phase (Type-checking, undeclared variables, scanf pointer checks)
  const semanticErrors = analyze(ast, tokens, source);

  // 6. Security Taint Scanning
  const secWarnings = scanSecurity(tokens, ast, source);

  // 7. Intermediate Representation & CFG
  const irInstrs = generateIR(ast);
  const cfgResult = buildCFG(irInstrs);

  // 8. Security Hardening Synthesis
  const hardenedData = generateHardenedCode(source, ast, tokens, secWarnings);

  // Combine and deduplicate all errors across all compiler phases
  const rawErrors = [...headerErrors, ...boilerErrors, ...lexErrors, ...parseErrors, ...semanticErrors];
  const seenErrorKeys = new Set();
  const dedupedErrors = [];
  for (const err of rawErrors) {
    const key = `${err.type}:${err.line}:${err.col || 1}:${err.raw || err.msg}`;
    if (!seenErrorKeys.has(key)) {
      seenErrorKeys.add(key);
      dedupedErrors.push(err);
    }
  }

  // Attach AST Contexts
  const allErrors = attachASTContexts(dedupedErrors, ast);

  // Security Health Calculation
  const secReport = calculateSecurityScore(secWarnings, source);

  // Execute the Multi-Agent Orchestration (HeaderGuard, BoilerplateAuditor, LexiScan, GrammarGuard, SemScope, OptiGen, SecurAudit, AutoFix)
  const orchestration = runAgentOrchestration(source, {
    tokens: vis,
    ast,
    errors: allErrors,
    secWarnings,
    irInstrs,
    cfgResult,
    unusedHeaders
  });

  lastCompile = {
    language: 'c',
    tokens: vis,
    ast,
    errors: allErrors,
    secWarnings,
    irInstrs,
    cfgResult,
    source,
    hardenedData,
    secReport,
    orchestration,
    symbols: analyze._lastSymbols || []
  };
  lastOrchestration = orchestration;

  // Render all views
  finishCompile(vis, allErrors, semanticErrors, secWarnings, irInstrs, cfgResult, secReport, orchestration, analyze._lastSymbols || []);

  // Trigger Peer-to-Peer Inter-Agent Coordination Bus
  if (typeof AgentNetwork !== 'undefined' && AgentNetwork.startNegotiation) {
    AgentNetwork.startNegotiation(source, lastCompile);
  }
}

function runLightweightSensing() {
  if (!codeInput) return;
  const source = codeInput.value;
  if (!source.trim()) return;

  const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';
  if (currentLang !== 'c' && typeof MultiLangEngine !== 'undefined') {
    const mlResult = MultiLangEngine.compile(source, currentLang);
    if (mlResult) {
      const sensingData = (typeof generateAISensingData === 'function')
        ? generateAISensingData(source, { errors: mlResult.errors, secWarnings: mlResult.secWarnings }, mlResult.orchestration)
        : [];
      renderBesideCodeAISensing(sensingData);
      return;
    }
  }

  const { tokens, errors: lexErrors } = lex(source);
  const { errors: headerErrors, includedHeaders } = validatePreprocessorAndHeaders(source, tokens);
  const pResult = parse(tokens, source, includedHeaders);
  const ast = pResult.ast || { kind: 'Program', children: [] };
  const parseErrors = (pResult.errors || []).filter(e => e.type === 'ParseError');
  const boilerErrors = validateBoilerplateAndStructure(source, tokens, ast);
  const semanticErrors = analyze(ast, tokens, source);
  const secWarnings = scanSecurity(tokens, ast, source);

  const rawErrors = [...headerErrors, ...boilerErrors, ...lexErrors, ...parseErrors, ...semanticErrors];
  const seenErrorKeys = new Set();
  const dedupedErrors = [];
  for (const err of rawErrors) {
    const key = `${err.type}:${err.line}:${err.col || 1}:${err.raw || err.msg}`;
    if (!seenErrorKeys.has(key)) {
      seenErrorKeys.add(key);
      dedupedErrors.push(err);
    }
  }
  const allErrors = attachASTContexts(dedupedErrors, ast);

  const orchestration = (typeof runAgentOrchestration === 'function') ? runAgentOrchestration(source, {
    tokens,
    ast,
    errors: allErrors,
    secWarnings,
    irInstrs: [],
    cfgResult: null
  }) : null;

  const sensingData = generateAISensingData(source, { errors: allErrors, secWarnings }, orchestration);
  renderBesideCodeAISensing(sensingData);
}

function finishCompile(vis, allErrors, semanticErrors, secWarnings, irInstrs, cfgResult, secReport, orchestration, symbols = null) {
  // Update header and stat bar
  const statTokens = document.getElementById('stat-tokens');
  const statErrors = document.getElementById('stat-errors');
  const statSecScore = document.getElementById('stat-sec-score');
  const statPhase = document.getElementById('stat-phase');
  const headerSec = document.getElementById('headerSecBadge');

  if (statTokens) statTokens.textContent = vis.length;
  if (statErrors) statErrors.textContent = allErrors.length;
  if (statSecScore) {
    statSecScore.textContent = `${secReport.scorePercentage}%`;
    statSecScore.style.color = secReport.badgeColor;
  }
  if (headerSec) {
    headerSec.textContent = `⚡ Security: ${secReport.scorePercentage}% (${secReport.grade})`;
    headerSec.style.borderColor = secReport.badgeColor;
    headerSec.style.color = secReport.badgeColor;
  }
  if (statPhase) {
    statPhase.textContent = allErrors.length > 0 ? 'FIX NEEDED' : 'PASSED ✓';
    statPhase.style.color = allErrors.length > 0 ? 'var(--red)' : 'var(--green)';
  }

  // Update Health Ribbon
  renderHealthRibbon(allErrors.length, secReport);

  // Update Agent Pipeline Strip
  renderAgentPipelineBadges(orchestration);

  // Render Agent Reports in Tab 1
  renderAgentReports(orchestration);

  // Render Beside-the-code AI Sensing
  const sensingList = generateAISensingData(lastCompile.source, lastCompile, orchestration);
  renderBesideCodeAISensing(sensingList);

  // Render AST, Tokens, Security, IR, Symbols
  const activeSymbols = symbols || (lastCompile && lastCompile.symbols) || (typeof analyze !== 'undefined' && analyze._lastSymbols) || [];
  try {
    renderTokens(vis);
  } catch (errTokens) {
    console.error('[NeuralCC] renderTokens error:', errTokens);
  }
  try {
    renderAST(lastCompile.ast);
  } catch (errAST) {
    console.error('[NeuralCC] renderAST error:', errAST);
  }
  try {
    renderIR(irInstrs || [], cfgResult || null, secWarnings);
  } catch (errIR) {
    console.error('[NeuralCC] renderIR error:', errIR);
  }
  try {
    renderSymbols(activeSymbols);
  } catch (errSym) {
    console.error('[NeuralCC] renderSymbols error:', errSym);
  }

  if (lastCompile.hardenedData) {
    try {
      renderHardenedCode(lastCompile.hardenedData, lastCompile.source);
    } catch (errHard) {
      console.error('[NeuralCC] renderHardenedCode error:', errHard);
    }
  }

  updateTabBadges(allErrors.length, secWarnings.length, sensingList.length);

  // Keep user on their chosen tab (e.g. Multi-Agent Reports, Terminal, etc.)
  // Only auto-route on initial run or if explicitly on sensing
  if (!currentUserTab || currentUserTab === 'sensing') {
    if (allErrors.length > 0) {
      switchTab('sensing');
    } else if (secWarnings.length > 0) {
      switchTab('secure');
    }
  }
}

// ════════════════════════════════════════════════════
//  HEALTH RIBBON & PIPELINE BADGES
// ════════════════════════════════════════════════════
function renderHealthRibbon(errorCount, secReport) {
  const diagCount = document.getElementById('diagCount');
  const diagSub = document.getElementById('diagSub');
  const healthSecScore = document.getElementById('healthSecScore');
  const healthSecGrade = document.getElementById('healthSecGrade');

  const hasSecWarnings = secReport && secReport.deductions && secReport.deductions.length > 0;

  if (diagCount) {
    if (errorCount === 0 && hasSecWarnings) {
      diagCount.textContent = '🛑 VETO ACTIVE';
      diagCount.style.color = '#ef4444';
    } else {
      diagCount.textContent = errorCount === 0 ? '0 Errors' : `${errorCount} Fault${errorCount > 1 ? 's' : ''}`;
      diagCount.style.color = errorCount === 0 ? 'var(--green)' : 'var(--red)';
    }
  }
  if (diagSub) {
    if (hasSecWarnings) {
      diagSub.textContent = 'SecurAudit Veto: Memory risk detected';
      diagSub.style.color = '#ef4444';
    } else {
      diagSub.textContent = errorCount === 0 ? 'Syntax & Scope 100% Valid' : 'Click "Auto-Correct" to fix';
      diagSub.style.color = '';
    }
  }
  if (healthSecScore) {
    healthSecScore.textContent = `${secReport.scorePercentage}%`;
    healthSecScore.style.color = secReport.badgeColor;
  }
  if (healthSecGrade) {
    healthSecGrade.textContent = `Grade ${secReport.grade} (${secReport.statusText})`;
    healthSecGrade.style.color = secReport.badgeColor;
  }
}

function renderAgentPipelineBadges(orchestration) {
  if (!orchestration) return;
  const mapping = [
    { key: 'header', agent: orchestration.headerGuard },
    { key: 'boiler', agent: orchestration.boilerplateAuditor },
    { key: 'lex', agent: orchestration.lexiScan },
    { key: 'parse', agent: orchestration.grammarGuard },
    { key: 'sem', agent: orchestration.semScope },
    { key: 'ir', agent: orchestration.optiGen },
    { key: 'sec', agent: orchestration.securAudit }
  ];

  mapping.forEach(m => {
    if (!m.agent) return;
    const dot = document.getElementById(`dot-${m.key}`);
    const pill = document.getElementById(`agent-pill-${m.key}`);
    if (dot) {
      dot.className = 'agent-dot ' + (m.agent.status === 'ok' ? '' : (m.agent.status === 'critical' || m.agent.status === 'error' ? 'error' : 'warning'));
    }
  });
}

function filterAgentView(agentKey) {
  switchTab('agents');
  const targetId = `agent-card-${agentKey}`;
  const el = document.getElementById(targetId);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.boxShadow = '0 0 15px rgba(2, 132, 199, 0.4)';
    setTimeout(() => { el.style.boxShadow = ''; }, 1600);
  }
}

// ════════════════════════════════════════════════════
//  MULTI-AGENT REPORTS RENDERING (Tab 1)
// ════════════════════════════════════════════════════
function renderAgentReports(orchestration) {
  const container = document.getElementById('agentReportsList');
  if (!container || !orchestration) return;

  const agentList = [
    { key: 'header', phaseNum: '0', phaseTitle: 'Phase 0: Preprocessor & Standard Headers', data: orchestration.headerGuard },
    { key: 'boiler', phaseNum: '0.5', phaseTitle: 'Phase 0.5: Structure & Program Entry', data: orchestration.boilerplateAuditor },
    { key: 'lex', phaseNum: '1', phaseTitle: 'Phase 1: Lexical & Token Stream Analysis', data: orchestration.lexiScan },
    { key: 'parse', phaseNum: '2', phaseTitle: 'Phase 2: Syntax & Context-Free Grammar (AST)', data: orchestration.grammarGuard },
    { key: 'sem', phaseNum: '3', phaseTitle: 'Phase 3: Semantic Scope & Type Verification', data: orchestration.semScope },
    { key: 'ir', phaseNum: '4', phaseTitle: 'Phase 4: Intermediate Representation (TAC & CFG)', data: orchestration.optiGen },
    { key: 'sec', phaseNum: '5', phaseTitle: 'Phase 5: Security Surface & Memory Exploit Audit', data: orchestration.securAudit },
    { key: 'autofix', phaseNum: '6', phaseTitle: 'Phase 6: Autonomous Program Repair (APR Engine)', data: orchestration.autoFix }
  ];

  let html = '';
  agentList.forEach(a => {
    const ag = a.data;
    if (!ag) return;

    const hasErrors = ag.status === 'error' || ag.status === 'critical';
    const isReadyFix = ag.status === 'ready';
    const isWarning = ag.status === 'warning';
    const isOk = ag.status === 'ok';

    const statusCls = isOk ? 'ok' : (hasErrors ? 'error' : (isReadyFix ? 'ready' : (isWarning ? 'warning' : 'idle')));
    
    let statusText = 'Phase Passed ✓';
    if (hasErrors) {
      const errCount = (ag.findings && ag.findings.length) || 1;
      statusText = `${errCount} Fault${errCount > 1 ? 's' : ''} Detected ⚠`;
    } else if (isReadyFix) {
      statusText = 'Ready to Auto-Repair ✨';
    } else if (isWarning) {
      statusText = 'Audit Notice ℹ';
    }

    html += `
      <div class="agent-report-card ${statusCls}" id="agent-card-${a.key}">
        <div class="agent-report-head">
          <div class="agent-head-left">
            <span class="agent-report-icon">${ag.icon}</span>
            <div class="agent-head-meta">
              <span class="agent-phase-pill">${esc(ag.phase || a.phaseTitle)}</span>
              <div class="agent-title-row">
                <strong class="agent-name-text">${esc(ag.name)}</strong>
                <span class="agent-role-sep">·</span>
                <span class="agent-role-text">${esc(ag.role)}</span>
              </div>
            </div>
          </div>
          <div class="agent-head-right">
            <span class="agent-report-status ${statusCls}">${statusText}</span>
          </div>
        </div>
        <div class="agent-report-body">
          <div class="agent-report-summary ${statusCls}">
            <span class="summary-dot"></span>
            <span>${esc(ag.summary)}</span>
          </div>`;

    if (a.key === 'autofix' && ag.proposedFixes && ag.proposedFixes.length > 0) {
      html += `<div class="agent-findings-container">
        <div class="findings-header-label">⚡ Autonomous Synthesis Candidates (${ag.proposedFixes.length} Actionable Fixes):</div>`;
      ag.proposedFixes.forEach((pf, idx) => {
        html += `
          <div class="agent-finding-item autofix-item">
            <div class="agent-finding-head-row">
              <span class="finding-line-badge">Line ${pf.line}</span>
              <strong class="finding-issue-title">${esc(pf.description)}</strong>
              <span class="badge b-ast">${esc(pf.type)} Fix</span>
            </div>
            <div class="agent-finding-code-diff">
              <span class="diff-lbl">Synthesized Replacement:</span>
              <code class="diff-code">${esc(pf.fix)}</code>
            </div>
          </div>`;
      });
      html += `
        <button class="btn-micro-autocorrect" onclick="triggerAutoCorrect()">
          ✨ 1-Click Auto-Correct All (${ag.proposedFixes.length} Fixes)
        </button>
      </div>`;
    } else if (ag.findings && ag.findings.length > 0) {
      html += `<div class="agent-findings-container">
        <div class="findings-header-label">🔍 Diagnostic Findings & Root Cause Analysis (${ag.findings.length}):</div>`;
      ag.findings.forEach(f => {
        html += `
          <div class="agent-finding-item ${f.severity ? 'sec-finding' : ''}">
            <div class="agent-finding-head-row">
              <span class="finding-line-badge">Line ${f.line || 1}</span>
              <strong class="finding-issue-title">${esc(f.issue)}</strong>
              ${f.severity ? `<span class="badge b-sec">${esc(f.severity)}</span>` : ''}
            </div>
            <div class="agent-finding-detail-row">
              <span class="detail-tag why">Diagnosis:</span>
              <span class="detail-text">${esc(f.why)}</span>
            </div>
            <div class="agent-finding-detail-row">
              <span class="detail-tag remedy">Remedy:</span>
              <span class="detail-text remedy-text">${esc(f.whatToAdd)}</span>
            </div>
          </div>`;
      });
      html += `</div>`;
    }

    html += `
        </div>
      </div>`;
  });

  container.innerHTML = html;
}
function triggerAutoCorrect(forceDirect = false) {
  if (!codeInput) return;
  const source = codeInput.value;
  if (!source.trim()) {
    showToast('Editor is empty. Write code or select a preset!');
    return;
  }

  const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';
  let result;
  if (currentLang !== 'c' && typeof MultiLangEngine !== 'undefined') {
    result = MultiLangEngine.autoCorrect(source, currentLang);
  } else {
    result = autoCorrectSourceCode(source, lastCompile);
  }

  if (!result.changesMade || result.correctedSource === source) {
    showToast(`✓ Code is already 100% syntactically & semantically valid!`);
    return;
  }

  if (forceDirect) {
    codeInput.value = result.correctedSource;
    updateLineNums();
    runCompiler();
    showToast(`✨ Auto-Correct: Repaired ${result.fixesApplied.length} compiler fault(s) in ${currentLang.toUpperCase()} automatically!`);
  } else {
    // Open Diff Inspector preview so the user sees all changes before applying!
    if (typeof openDiffInspector === 'function') {
      openDiffInspector(result);
      showToast(`🔍 Previewing ${result.fixesApplied.length} proposed fix(es). Click "✨ Apply Patch to Editor" to confirm.`);
    } else {
      codeInput.value = result.correctedSource;
      updateLineNums();
      runCompiler();
      showToast(`✨ Auto-Correct: Repaired ${result.fixesApplied.length} compiler fault(s)!`);
    }
  }
}

// ════════════════════════════════════════════════════
//  ONE-CLICK SECURE CODE GENERATOR
// ════════════════════════════════════════════════════
function runAutoSecure() {
  if (!codeInput) return;
  if (!lastCompile || !lastCompile.hardenedData) {
    runCompiler().then(() => {
      applySecureCodeToEditor();
    });
    return;
  }
  applySecureCodeToEditor();
}

function applySecureCodeToEditor() {
  if (!lastCompile || !lastCompile.hardenedData) return;
  const hard = lastCompile.hardenedData.hardenedSource;
  if (!hard) return;

  codeInput.value = hard;
  updateLineNums();
  runCompiler();
  switchTab('secure');
  showToast('🛡️ 100% Hardened Code Applied to Editor!');
}

function copyHardenedCode() {
  if (!lastCompile || !lastCompile.hardenedData) return;
  const hard = lastCompile.hardenedData.hardenedSource;
  if (!hard) return;

  navigator.clipboard.writeText(hard).then(() => {
    showToast('📋 Hardened Code Copied to Clipboard!');
  });
}

// ════════════════════════════════════════════════════
//  IN-BROWSER VIRTUAL C EXECUTION ENGINE
// ════════════════════════════════════════════════════
function runVirtualProgram() {
  if (!codeInput) return;
  const source = codeInput.value;
  if (!source.trim()) {
    showToast('Editor is empty. Write or load code first!');
    return;
  }

  // Switch to the virtual terminal tab
  switchTab('terminal');

  const termScreen = document.getElementById('terminalScreen');
  const termPill = document.getElementById('terminalStatusPill');
  const mExit = document.getElementById('m-term-exit');
  const mTime = document.getElementById('m-term-time');
  const mInstr = document.getElementById('m-term-instr');
  const mMem = document.getElementById('m-term-mem');

  if (termPill) {
    termPill.className = 'terminal-status-pill running';
    termPill.textContent = 'RUNNING';
  }

  // Ensure fresh compile if needed
  if (!lastCompile || lastCompile.source !== source) {
    runCompiler();
  }

  const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';
  const langCfg = (typeof MultiLangEngine !== 'undefined')
    ? MultiLangEngine.getConfig(currentLang)
    : { standard: 'ISO C11', runCommand: 'gcc main.c -o main.out && ./main.out' };

  // 1. Check if compiler errors exist
  if (lastCompile && lastCompile.errors && lastCompile.errors.length > 0) {
    if (termPill) {
      termPill.className = 'terminal-status-pill fault';
      termPill.textContent = 'COMPILE FAULT';
    }
    if (termScreen) {
      termScreen.innerHTML = `
        <div class="terminal-banner">
          NeuralCC Virtual Execution Engine (${langCfg.standard})
        </div>
        <div style="color:#ef4444;margin-bottom:8px;">
          ❌ [COMPILATION HALTED] Execution blocked by syntax/compiler errors:
        </div>
        ${lastCompile.errors.map((e, idx) => `<div style="color:#f87171;font-size:0.75rem;">  • Line ${e.line}: ${esc(e.raw)}</div>`).join('')}
        <div style="color:#38bdf8;margin-top:12px;">
          💡 Tip: Click <strong>"✨ Auto-Correct"</strong> or <strong>"✨ Fix Errors"</strong> to repair the code automatically.
        </div>
        <div class="terminal-line" style="margin-top:12px;"><span class="terminal-prompt">user@neuralcc:~$</span> <span class="terminal-cursor">_</span></div>
      `;
    }
    showToast(`Execution blocked: ${lastCompile.errors.length} compile error(s) present.`);
    return;
  }

  // 2. Check for active security veto on unhardened dangerous functions
  if (lastCompile && lastCompile.secWarnings && lastCompile.secWarnings.length > 0) {
    const primarySec = lastCompile.secWarnings[0];
    if (primarySec.severity === 'CRITICAL' && (primarySec.fn === 'gets' || primarySec.fn === 'eval' || primarySec.fn === 'os.system')) {
      if (termPill) {
        termPill.className = 'terminal-status-pill fault';
        termPill.textContent = 'SECURITY VETO';
      }
      if (termScreen) {
        termScreen.innerHTML = `
          <div class="terminal-banner">
            NeuralCC Virtual Execution Engine (${langCfg.standard})
          </div>
          <div style="color:#ef4444;font-weight:700;margin-bottom:8px;">
            🛑 [SECURITY VETO ACTIVE] Execution Blocked by SecurAudit Sentinel!
          </div>
          <div style="color:#fca5a5;line-height:1.5;">
            Detected critical security risk: <strong>${esc(primarySec.fn)}</strong> [${esc(primarySec.cwe)} - ${esc(primarySec.name)}]<br>
            Threat: ${esc(primarySec.msg)}
          </div>
          <div style="color:#38bdf8;margin-top:12px;">
            🛡️ Click <strong>"✨ Auto-Correct"</strong> to remove or sanitize dangerous code.
          </div>
          <div class="terminal-line" style="margin-top:12px;"><span class="terminal-prompt">user@neuralcc:~$</span> <span class="terminal-cursor">_</span></div>
        `;
      }
      showToast(`Execution blocked: Active Security Veto on ${primarySec.fn}`);
      return;
    }
  }

  // 3. Execute through MultiLangEngine or VirtualCRuntime
  let result;
  if (currentLang !== 'c' && typeof MultiLangEngine !== 'undefined') {
    result = MultiLangEngine.execute(source, currentLang, lastCompile ? lastCompile.ast : null);
  } else {
    if (typeof VirtualCRuntime === 'undefined') {
      showToast('Virtual C Runtime is initializing...');
      return;
    }
    result = VirtualCRuntime.executeAST(lastCompile.ast, source);
  }

  if (mExit) mExit.textContent = result.exitCode;
  if (mTime) mTime.textContent = result.metrics.executionTimeMs + ' ms';
  if (mInstr) mInstr.textContent = result.metrics.instructionsExecuted;
  if (mMem) mMem.textContent = (result.metrics.memoryAllocatedBytes / 1024).toFixed(1) + ' KB';

  if (result.success) {
    if (termPill) {
      termPill.className = 'terminal-status-pill success';
      termPill.textContent = `EXIT: ${result.exitCode}`;
    }
    if (termScreen) {
      const cleanOut = esc(result.output).replace(/\n/g, '<br>');
      termScreen.innerHTML = `
        <div class="terminal-banner">
          NeuralCC Virtual Execution Engine (${langCfg.standard})
        </div>
        <div class="terminal-line"><span class="terminal-prompt">user@neuralcc:~$</span> ${langCfg.runCommand}</div>
        <div style="color:#f1f5f9;margin-top:6px;line-height:1.5;">${cleanOut}</div>
        <div class="terminal-line" style="margin-top:8px;"><span class="terminal-prompt">user@neuralcc:~$</span> <span class="terminal-cursor">_</span></div>
      `;
    }
    showToast(`▶ Process exited with code ${result.exitCode} (${result.metrics.executionTimeMs} ms)`);
  } else {
    if (termPill) {
      termPill.className = 'terminal-status-pill fault';
      termPill.textContent = 'RUNTIME ERROR';
    }
    if (termScreen) {
      const cleanOut = esc(result.output || result.errors).replace(/\n/g, '<br>');
      termScreen.innerHTML = `
        <div class="terminal-banner">
          NeuralCC Virtual Execution Engine (${langCfg.standard})
        </div>
        <div style="color:#ef4444;margin-bottom:8px;">❌ Runtime Exception encountered:</div>
        <div style="color:#f87171;">${cleanOut}</div>
        <div class="terminal-line" style="margin-top:8px;"><span class="terminal-prompt">user@neuralcc:~$</span> <span class="terminal-cursor">_</span></div>
      `;
    }
    showToast('Runtime fault encountered during execution.');
  }
}

function clearTerminal() {
  const termScreen = document.getElementById('terminalScreen');
  const termPill = document.getElementById('terminalStatusPill');
  const mExit = document.getElementById('m-term-exit');
  const mTime = document.getElementById('m-term-time');
  const mInstr = document.getElementById('m-term-instr');

  if (termScreen) {
    termScreen.innerHTML = `
      <div class="terminal-banner">
        NeuralCC In-Browser Virtual C Execution Engine v2.4 (GCC 14 / ISO C11 ABI)<br>
        Type code in the editor and click "⚡ Run Program" to execute main().
      </div>
      <div class="terminal-line"><span class="terminal-prompt">user@neuralcc:~$</span> <span class="terminal-cursor">_</span></div>
    `;
  }
  if (termPill) {
    termPill.className = 'terminal-status-pill';
    termPill.textContent = 'READY';
  }
  if (mExit) mExit.textContent = '-';
  if (mTime) mTime.textContent = '0.00 ms';
  if (mInstr) mInstr.textContent = '0';
  if (typeof VirtualCRuntime !== 'undefined') VirtualCRuntime.reset();
  showToast('Terminal Cleared');
}

function handleTerminalStdin(event) {
  if (event.key === 'Enter') {
    const inputEl = document.getElementById('terminalStdinInput');
    if (!inputEl) return;
    const val = inputEl.value;
    inputEl.value = '';
    if (typeof VirtualCRuntime !== 'undefined') {
      VirtualCRuntime.inputQueue.push(val + '\n');
    }
    const termScreen = document.getElementById('terminalScreen');
    if (termScreen) {
      const line = document.createElement('div');
      line.style.color = '#38bdf8';
      line.textContent = `stdin > ${val}`;
      termScreen.appendChild(line);
      termScreen.scrollTop = termScreen.scrollHeight;
    }
  }
}

// ════════════════════════════════════════════════════
//  RENDER TOKENS, AST, IR, SECURITY, SYMBOLS
// ════════════════════════════════════════════════════
function renderTokens(tokens) {
  const el = document.getElementById('tokenStream');
  if (!el) return;
  if (!tokens || !tokens.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div>No tokens scanned</div>';
    return;
  }
  const cls = { KEYWORD: 'tok-keyword', IDENTIFIER: 'tok-identifier', NUMBER: 'tok-number', STRING: 'tok-string', OPERATOR: 'tok-operator', PUNCTUATION: 'tok-punctuation', ERROR: 'tok-error' };
  el.innerHTML = tokens.map((t, i) => `<span class="tok ${cls[t.type] || 'tok-punctuation'}" title="${t.type} @ L${t.line}:${t.col}" style="animation-delay:${i * 6}ms">${esc(t.value)}</span>`).join('');
}

function renderAST(ast) {
  const el = document.getElementById('astView');
  if (!el) return;
  el.innerHTML = renderASTNode(ast, 0);
}

function renderASTNode(node, depth) {
  if (!node || typeof node !== 'object') return '';
  let inner = `<span class="ast-kind">${node.kind}</span>`;
  if (node.name) inner += ` <span class="ast-name">"${esc(node.name)}"</span>`;
  if (node.varType) inner += ` <span class="ast-type">:${node.varType}</span>`;
  if (node.returnType) inner += ` <span class="ast-type">→${node.returnType}</span>`;
  if (node.line) inner += `<span class="ast-line">L${node.line}</span>`;

  let ch = '';
  const keys = ['children', 'body', 'then', 'else', 'cond', 'init', 'update', 'left', 'right', 'expr', 'value', 'args', 'params', 'index'];
  for (const k of keys) {
    if (!node[k]) continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach(c => ch += renderASTNode(c, depth + 1));
    else if (typeof v === 'object') ch += renderASTNode(v, depth + 1);
  }
  return `<div class="ast-node" style="margin-left:${depth * 14}px"><div class="ast-node-inner">${inner}</div>${ch ? `<div class="ast-children">${ch}</div>` : ''}</div>`;
}

function renderHardenedCode(hardenedData, originalSource) {
  if (!hardenedData) return;
  const gb = document.getElementById('score-grade-before');
  const ga = document.getElementById('score-grade-after');
  const origPre = document.getElementById('compareOriginalCode');
  const hardPre = document.getElementById('compareHardenedCode');
  const badgeCount = document.getElementById('badge-vuln-count');
  const ledger = document.getElementById('transformLedger');

  if (gb) gb.textContent = hardenedData.gradeBefore;
  if (ga) ga.textContent = hardenedData.gradeAfter;
  if (origPre) origPre.textContent = originalSource || '// No code provided';
  if (hardPre) hardPre.textContent = hardenedData.hardenedSource;
  if (badgeCount) badgeCount.textContent = `${hardenedData.totalFixed} Vulnerabilit${hardenedData.totalFixed === 1 ? 'y' : 'ies'}`;

  if (ledger) {
    if (!hardenedData.transformations.length) {
      ledger.innerHTML = '<div class="empty-state"><div class="empty-icon">✓</div><div class="empty-title" style="color:var(--green)">100% Clean Code</div><div class="empty-desc">Zero memory risks or vulnerable C function invocations found in this source file.</div></div>';
    } else {
      ledger.innerHTML = hardenedData.transformations.map((t, idx) => `
        <div class="transform-card" style="animation-delay:${idx * 40}ms">
          <div class="transform-head">
            <span class="transform-cwe">${esc(t.cwe)} — ${esc(t.name)}</span>
            <span class="transform-line">Line ${t.line}</span>
          </div>
          <div class="transform-body">
            <strong>Exploit Neutralized:</strong> ${esc(t.exploitBlocked)}<br>
            <strong>Mitigation Strategy:</strong> ${esc(t.fixReason)}
          </div>
          <div class="transform-code-diff">
            <div class="diff-orig">- ${esc(t.original)}</div>
            <div class="diff-hard">+ ${esc(t.hardened)}</div>
          </div>
        </div>
      `).join('');
    }
  }
}

function renderIR(instrs, cfgResult, secWarnings) {
  const el = document.getElementById('irView');
  if (!el) return;
  if (!instrs || !instrs.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">⟐</div>No IR generated — compile code first</div>';
    return;
  }
  const blockMap = new Map();
  instrs.forEach(ins => {
    const bid = ins.blockId || 'B_ENTRY';
    if (!blockMap.has(bid)) blockMap.set(bid, []);
    blockMap.get(bid).push(ins);
  });
  let html = '', addr = 0;
  blockMap.forEach((binstr, bid) => {
    html += `<div class="ir-block"><div class="ir-block-head"><span class="ir-block-label">⟐ ${esc(bid)}</span></div><div class="ir-block-body">`;
    binstr.forEach(ins => {
      const isSec = ins.op.startsWith('canary_') || ins.op.startsWith('bounds_');
      const opColor = isSec ? '#10b981' : 'var(--cyan)';
      const secTag = isSec ? ' <span class="badge b-ast" style="font-size:0.48rem;padding:2px 6px;margin-left:6px">🛡️ Compiler Guard</span>' : '';
      const args = [ins.result, ins.arg1, ins.arg2].filter(Boolean).map(a => esc(a)).join(', ');
      html += `<div class="ir-instr" style="${isSec ? 'background:rgba(16,185,129,0.06);border-left:2px solid #10b981;padding-left:6px' : ''}"><span class="ir-addr">${addr++}</span><span class="ir-op" style="color:${opColor};font-weight:700">${esc(ins.op)}</span> ${args ? `<span class="ir-result">${args}</span>` : ''}${secTag}</div>`;
    });
    html += '</div></div>';
  });
  el.innerHTML = html;
}

function renderSymbols(symbols) {
  const el = document.getElementById('symbolView');
  if (!el) return;
  if (!symbols || !symbols.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">⊞</div>Symbol table empty — compile code to resolve identifiers</div>';
  } else {
    el.innerHTML = `
      <div class="sym-scope">
        <div class="sym-scope-head">SEMANTIC SCOPE SYMBOLS (${symbols.length} IDENTIFIERS)</div>
        <table class="sym-table">
          <thead>
            <tr><th>Identifier</th><th>Type</th><th>Line</th></tr>
          </thead>
          <tbody>
            ${symbols.map(s => `<tr><td><span class="sym-kind-var">${esc(s.name)}</span></td><td><span class="sym-type">${esc(s.returnType || s.type || 'var')}</span></td><td><span class="sym-line">L${s.line || 1}</span></td></tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  }
}

function updateTabBadges(errors, sec, sensing = 0) {
  const eb = document.getElementById('tbadge-errors');
  const sb = document.getElementById('tbadge-security');
  const tb = document.getElementById('tbadge-sensing');
  if (eb) {
    eb.textContent = errors;
    eb.style.display = errors > 0 ? 'inline-block' : 'none';
  }
  if (sb) {
    sb.textContent = sec;
    sb.style.display = sec > 0 ? 'inline-block' : 'none';
  }
  if (tb) {
    tb.textContent = sensing;
    tb.style.display = sensing > 0 ? 'inline-block' : 'none';
  }
}

// ════════════════════════════════════════════════════
//  HACKER EXPLOIT SIMULATOR (Viva Showcase)
// ════════════════════════════════════════════════════
let simCurrentMode = 'unprotected';

function updateSimMode() {
  const radio = document.querySelector('input[name="simMode"]:checked');
  simCurrentMode = radio ? radio.value : 'unprotected';
  resetExploitSim();
}

function resetExploitSim() {
  const buf = document.getElementById('stk-buffer');
  const bufVal = document.getElementById('stk-buffer-val');
  const canary = document.getElementById('stk-canary');
  const canaryVal = document.getElementById('stk-canary-val');
  const ebp = document.getElementById('stk-ebp');
  const ebpVal = document.getElementById('stk-ebp-val');
  const eip = document.getElementById('stk-eip');
  const eipVal = document.getElementById('stk-eip-val');
  const consoleEl = document.getElementById('exploitConsole');

  if (buf) { buf.className = 'stack-block'; bufVal.textContent = '0x0000000000000000 (Empty Initial State)'; }
  if (canary) { canary.className = 'stack-block canary'; canaryVal.textContent = '0x5A7C89F1 (Secret Guard Value)'; }
  if (ebp) { ebp.className = 'stack-block'; ebpVal.textContent = '0x7FFFFFFFE480'; }
  if (eip) { eip.className = 'stack-block return-addr'; eipVal.textContent = '0x00401142 (main() Caller Exit)'; }

  if (consoleEl) {
    consoleEl.innerHTML = `<div class="console-line status">// Exploit simulator reset. Target Mode: ${simCurrentMode.toUpperCase()}.</div>`;
  }
}

function launchExploitAnimation() {
  const buf = document.getElementById('stk-buffer');
  const bufVal = document.getElementById('stk-buffer-val');
  const canary = document.getElementById('stk-canary');
  const canaryVal = document.getElementById('stk-canary-val');
  const ebp = document.getElementById('stk-ebp');
  const ebpVal = document.getElementById('stk-ebp-val');
  const eip = document.getElementById('stk-eip');
  const eipVal = document.getElementById('stk-eip-val');
  const consoleEl = document.getElementById('exploitConsole');

  resetExploitSim();
  const log = (msg, cls = 'status') => {
    const d = document.createElement('div');
    d.className = 'console-line ' + cls;
    d.textContent = msg;
    consoleEl.appendChild(d);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  };

  log(`[+] Attacker payload injected into stdin stream...`, 'warning');

  setTimeout(() => {
    buf.className = 'stack-block corrupted';
    bufVal.textContent = '0x4141414141414141 ("AAAAAAAA" 64 Bytes Overflow)';
    log(`[!] char buf[64] buffer saturated (64 bytes filled)`, 'warning');
  }, 400);

  if (simCurrentMode === 'unprotected') {
    setTimeout(() => {
      canary.className = 'stack-block corrupted';
      canaryVal.textContent = '0x41414141 (CORRUPTED by Payload)';
      log(`[!] Unprotected Binary: Stack Canary missing! Attacker bytes overwrite adjacent stack frame.`, 'danger');
    }, 900);

    setTimeout(() => {
      ebp.className = 'stack-block corrupted';
      ebpVal.textContent = '0x41414141 (EBP Overwritten)';
      log(`[!] Saved Frame Pointer smashed: 0x41414141`, 'danger');
    }, 1400);

    setTimeout(() => {
      eip.className = 'stack-block corrupted';
      eipVal.textContent = '0xDEADBEEF (Hacker Shellcode Pointer!)';
      log(`[CRITICAL] Return Address (EIP) hijacked -> 0xDEADBEEF`, 'danger');
      log(`[EXPLOIT SUCCESSFUL] Attacker redirected CPU execution flow! Shell spawned (/bin/sh).`, 'danger');
    }, 1900);
  } else {
    // Hardened Mode
    setTimeout(() => {
      canary.className = 'stack-block protected';
      canaryVal.textContent = '0x5A7C89F1 (Canary Intact & Verified)';
      log(`[+] NeuralCC Stack Guard: Input bounded via fgets() / stack canary active`, 'success');
    }, 900);

    setTimeout(() => {
      ebp.className = 'stack-block protected';
      eip.className = 'stack-block protected';
      log(`[+] Stack Canary verified before function epilogue: 0x5A7C89F1 == 0x5A7C89F1`, 'success');
      log(`[SHIELD ACTIVE] Return Address (0x00401142) protected from tampering.`, 'success');
      log(`[EXPLOIT NEUTRALIZED] Zero stack corruption. Attack blocked 100%!`, 'success');
    }, 1500);
  }
}

// ════════════════════════════════════════════════════
//  PRESETS & WORKSPACE INITIALIZATION
// ════════════════════════════════════════════════════
const fallbackPresets = {
  header_fault: `include <std.io>\n\nint main() {\n    printf("Checking header error detection...\\n");\n    return 0;\n}`,
  boiler_fault: `#include <stdio.h>\n\nvoid mian() {\n    printf("Checking boilerplate ISO C compliance...\\n");\n}`,
  multi_error: `include <std.io>\n\nvoid mian() {\n    x = 10\n    printf("Total: %d\\n", x);\n}`,
  missing_semi: `int main() {\n    int x = 10\n    return 0;\n}`,
  missing_equal: `int main() {\n    int x 10;\n    int y = 20;\n    total x + y;\n    printf("Sum: %d\\n", total);\n    return 0;\n}`,
  unmatched: `int main() {\n    int x = 10;\n    if (x > 5) {\n        x = x * 2;\n    return 0;\n}`,
  undeclared: `int main() {\n    result = 10;\n    return 0;\n}`,
  buffer_overflow: `int main() {\n    char buf[64];\n    gets(buf); // Dangerous unbounded CWE-120\n    return 0;\n}`,
  hacker_overflow: `#include <stdio.h>\n\nint main() {\n    char buf[64];\n    printf("Enter username: ");\n    gets(buf); // Unbounded CWE-120 overflow vector\n    printf("Access granted!\\n");\n    return 0;\n}`,
  format_string: `#include <stdio.h>\n\nint main() {\n    char user_input[64];\n    gets(user_input);\n    printf(user_input); // CWE-134 Format string attack\n    return 0;\n}`,
  memory_leak: `int main() {\n    int* ptr = malloc(100);\n    ptr[0] = 42;\n    return 0;\n}`,
  heap_uaf: `#include <stdio.h>\n#include <stdlib.h>\n\nint main() {\n    int* ptr = malloc(64);\n    ptr[0] = 42;\n    printf("Allocated: %d\\n", ptr[0]);\n    free(ptr); // Pointer left dangling!\n    ptr[0] = 99; // Dangerous CWE-416 Use-After-Free dereference!\n    printf("Corrupted: %d\\n", ptr[0]);\n    return 0;\n}`,
  int_overflow: `#include <stdio.h>\n#include <stdlib.h>\n\nint main() {\n    unsigned short len1 = 65530;\n    unsigned short len2 = 100;\n    unsigned short total = len1 + len2; // Wraparound overflow CWE-190!\n    printf("Length: %d\\n", total);\n    char* buf = malloc(total);\n    return 0;\n}`,
  valid: `#include <stdio.h>\n\nint main() {\n    int x = 10;\n    printf("Value: %d\\n", x);\n    return 0;\n}`
};

const presets = (typeof ENTERPRISE_PRESETS !== 'undefined' && ENTERPRISE_PRESETS.c) ? ENTERPRISE_PRESETS.c : fallbackPresets;

function loadPreset(name) {
  const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';
  let langPresets = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getPresets(currentLang) : null;
  if (!langPresets && typeof ENTERPRISE_PRESETS !== 'undefined' && ENTERPRISE_PRESETS[currentLang]) {
    langPresets = ENTERPRISE_PRESETS[currentLang];
  }
  if (!langPresets) {
    langPresets = presets;
  }

  const selectedCode = (langPresets && langPresets[name]) || 
                       (typeof ENTERPRISE_PRESETS !== 'undefined' && ENTERPRISE_PRESETS.c && ENTERPRISE_PRESETS.c[name]) || 
                       presets[name];

  if (selectedCode && codeInput) {
    codeInput.value = selectedCode;
    updateLineNums();
    runCompiler();
  }
}

function setStudioLanguage(lang) {
  if (typeof MultiLangEngine === 'undefined') return;
  const cfg = MultiLangEngine.setLanguage(lang);

  // Update button active states
  ['c', 'cpp', 'java', 'python'].forEach(l => {
    const btn = document.getElementById(`lang-btn-${l}`);
    if (btn) {
      if (l === lang) btn.classList.add('active');
      else btn.classList.remove('active');
    }
  });

  // Update badges and titles
  const pill = document.getElementById('currentLangPill');
  if (pill) pill.textContent = `Active Frontend: ${cfg.name} Compiler (${cfg.standard})`;

  const badge = document.getElementById('headerLangBadge');
  if (badge) badge.textContent = cfg.compilerBadge;

  const title = document.getElementById('editorTitle');
  if (title) title.textContent = cfg.editorTitle;

  if (codeInput) {
    codeInput.placeholder = cfg.placeholder;
  }

  // Render presets for this language
  renderPresetChips(lang);

  // Load default preset for this language
  const presetsForLang = MultiLangEngine.getPresets(lang);
  const defaultPresetKey = Object.keys(presetsForLang)[0] || 'valid';
  loadPreset(defaultPresetKey);

  showToast(`Switched active compiler frontend to ${cfg.name} (${cfg.standard})`);
}

function renderPresetChips(lang) {
  const container = document.getElementById('presetChipsContainer');
  if (!container) return;

  if (lang === 'c') {
    container.innerHTML = `
      <button class="preset-btn" onclick="loadPreset('header_fault')">0. 📦 Header Faults</button>
      <button class="preset-btn" onclick="loadPreset('boiler_fault')">0.5 🏗️ Boilerplate Faults</button>
      <button class="preset-btn danger" onclick="loadPreset('multi_error')">⚡ All-in-One Multi-Fault</button>
      <button class="preset-btn" onclick="loadPreset('missing_semi')">1. Missing Semicolon ;</button>
      <button class="preset-btn" onclick="loadPreset('missing_equal')">1.5 Missing Equal =</button>
      <button class="preset-btn" onclick="loadPreset('unmatched')">2. Unmatched { }</button>
      <button class="preset-btn" onclick="loadPreset('undeclared')">3. Undeclared Var</button>
      <button class="preset-btn danger" style="background:#fee2e2;border-color:#ef4444;color:#b91c1c;font-weight:700;" onclick="loadPreset('buffer_overflow')">🚨 4. Security Veto: CWE-120 (gets)</button>
      <button class="preset-btn danger" onclick="loadPreset('hacker_overflow')">5. Hacker Stack Exploit</button>
      <button class="preset-btn warn" onclick="loadPreset('format_string')">6. Format Attack (printf)</button>
      <button class="preset-btn warn" onclick="loadPreset('memory_leak')">7. Mem Leak (malloc)</button>
      <button class="preset-btn danger" style="background:#fff1f2;border-color:#e11d48;color:#be123c;font-weight:700;" onclick="loadPreset('heap_uaf')">7.5. 🧠 Heap UAF &amp; Dangling (CWE-416)</button>
      <button class="preset-btn warn" style="background:#fff7ed;border-color:#ea580c;color:#c2410c;font-weight:700;" onclick="loadPreset('int_overflow')">7.8. 🔢 Integer Wraparound (CWE-190)</button>
      <button class="preset-btn success" onclick="loadPreset('valid')">8. Valid C Code (550 Lines)</button>
      <button class="preset-btn success" style="background:#ecfdf5;border-color:#059669;color:#047857;font-weight:700;" onclick="loadPreset('massive_enterprise')">🏛️ Massive Microkernel (3,600+ Lines)</button>
      <button class="preset-btn danger" style="border-color:#7c3aed;color:#7c3aed;background:rgba(124,58,237,0.06)" onclick="loadAAIAttackPreset('attack_policy_bypass')">⚡ AAI Attack: Policy Bypass</button>
      <button class="preset-btn danger" style="border-color:#7c3aed;color:#7c3aed;background:rgba(124,58,237,0.06)" onclick="loadAAIAttackPreset('attack_trojan_exfiltration')">⚡ AAI Attack: Trojan Backdoor</button>
    `;
    return;
  }

  if (lang === 'cpp') {
    container.innerHTML = `
      <button class="preset-btn danger" onclick="loadPreset('cpp_class_semi')">1. ❌ Missing ';' on Class</button>
      <button class="preset-btn warn" onclick="loadPreset('cpp_missing_stream')">2. ⚠️ Missing &lt;iostream&gt; / std::</button>
      <button class="preset-btn warn" onclick="loadPreset('cpp_stream_direction')">3. 🔄 Inverted Stream 'cout &gt;&gt;'</button>
      <button class="preset-btn success" onclick="loadPreset('cpp_oop_valid')">4. 🏛️ Valid C++ OOP Class</button>
      <button class="preset-btn danger" onclick="loadPreset('cpp_memory_leak')">5. 🚨 Leak: 'new' without 'delete'</button>
    `;
    return;
  }

  if (lang === 'java') {
    container.innerHTML = `
      <button class="preset-btn danger" onclick="loadPreset('java_missing_class')">1. ❌ Missing Class Wrapper</button>
      <button class="preset-btn warn" onclick="loadPreset('java_case_fault')">2. ⚠️ Case Mismatch: system.out</button>
      <button class="preset-btn danger" onclick="loadPreset('java_missing_semi')">3. ❌ Missing Semicolon ;</button>
      <button class="preset-btn danger" onclick="loadPreset('java_undeclared')">3.5. ⚖️ Undeclared Var</button>
      <button class="preset-btn success" onclick="loadPreset('java_valid')">4. ☕ Valid Java 17 Class</button>
      <button class="preset-btn danger" onclick="loadPreset('java_cmd_injection')">5. 🚨 CWE-78: Runtime.exec()</button>
    `;
    return;
  }

  if (lang === 'python') {
    container.innerHTML = `
      <button class="preset-btn danger" onclick="loadPreset('py_missing_colon')">1. ❌ Missing Colons (def/if)</button>
      <button class="preset-btn danger" onclick="loadPreset('py_indent_error')">2. 📐 Indentation Error</button>
      <button class="preset-btn warn" onclick="loadPreset('py_print_v2')">3. 🐍 Python 2 'print "..."'</button>
      <button class="preset-btn danger" onclick="loadPreset('py_undeclared')">3.5. ⚖️ Undeclared Var</button>
      <button class="preset-btn danger" onclick="loadPreset('py_security_eval')">4. 🚨 CWE-94: Insecure eval()</button>
      <button class="preset-btn success" onclick="loadPreset('py_valid')">5. ✨ Valid Python 3 Script</button>
    `;
    return;
  }
}

function clearAll() {
  if (codeInput) codeInput.value = '';
  updateLineNums();
  ['tokenStream', 'astView', 'irView', 'symbolView'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '<div class="empty-state"><div class="empty-icon">⬡</div>Compile code first</div>';
  });
  const drawer = document.getElementById('aiSensingDrawer');
  if (drawer) {
    drawer.innerHTML = `
      <div class="ai-sensing-empty">
        <div class="sensing-radar-ping"></div>
        <div class="sensing-empty-title">✦ AI Sensing Active</div>
        <div class="sensing-empty-sub">Type or compile your code to view instant diagnostics.</div>
      </div>`;
  }
  const reports = document.getElementById('agentReportsList');
  if (reports) {
    reports.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🤖</div>
        <div class="empty-title">All 6 Phase Agents Standing By</div>
        <div class="empty-desc">Click <strong>"▶ Compile Code"</strong> to run LexiScan, GrammarGuard, SemScope, OptiGen, and SecurAudit across your code.</div>
      </div>`;
  }
  const statTokens = document.getElementById('stat-tokens');
  const statErrors = document.getElementById('stat-errors');
  const statSec = document.getElementById('stat-sec-score');
  const statPhase = document.getElementById('stat-phase');
  if (statTokens) statTokens.textContent = '0';
  if (statErrors) statErrors.textContent = '0';
  if (statSec) statSec.textContent = '100%';
  if (statPhase) statPhase.textContent = 'IDLE';

  lastCompile = null;
  resetExploitSim();
  if (typeof AgentNetwork !== 'undefined') AgentNetwork.clear();
  clearTerminal();
  showToast('Workspace Cleared');
}

window.addEventListener('beforeunload', () => {
  sessionStorage.removeItem('_ncc_k');
  const el = document.getElementById('apiKey');
  if (el) el.value = '';
});

document.addEventListener('DOMContentLoaded', () => {
  const savedProvider = sessionStorage.getItem('_ncc_p');
  if (savedProvider) {
    const sel = document.getElementById('apiProvider');
    if (sel) sel.value = savedProvider;
  }
  loadPreset('missing_semi');
});

// ════════════════════════════════════════════════════
//  AGENTIC AI SECURITY SHIELD (AAISecShield) UI
// ════════════════════════════════════════════════════
function updateAAIShieldUI(result) {
  if (!result || typeof AAISecShield === 'undefined') return;

  const metrics = AAISecShield.getSecurityMetrics();
  const mAcc = document.getElementById('m-aai-acc');
  const mPrec = document.getElementById('m-aai-prec');
  const mRec = document.getElementById('m-aai-rec');
  const mF1 = document.getElementById('m-aai-f1');
  const mThreat = document.getElementById('m-aai-threat');
  const mLat = document.getElementById('m-aai-lat');
  const mBlocked = document.getElementById('m-aai-blocked');

  if (mAcc) mAcc.textContent = metrics.accuracyScore + '%';
  if (mPrec) mPrec.textContent = metrics.precisionScore + '%';
  if (mRec) mRec.textContent = metrics.recallScore + '%';
  if (mF1) mF1.textContent = metrics.f1Score.toFixed(2);
  if (mThreat) mThreat.textContent = result.threatScore.toFixed(1) + ' / 10';
  if (mLat) mLat.textContent = result.latencyMs + ' ms';
  if (mBlocked) mBlocked.textContent = String(metrics.attacksBlocked);

  const heroCard = document.getElementById('aaiHeroCard');
  const statusPill = document.getElementById('aaiStatusPill');
  const alertBanner = document.getElementById('aaiAlertBanner');
  const alertBadge = document.getElementById('aaiAlertBadge');
  const alertDetail = document.getElementById('aaiAlertDetail');
  const tabBadge = document.getElementById('tbadge-aai');

  if (result.status === 'ATTACK_BLOCKED') {
    if (heroCard) heroCard.className = 'aai-hero-card intercepted';
    if (statusPill) {
      statusPill.className = 'aai-status-pill blocked';
      statusPill.innerHTML = '<span class="live-dot" style="background:#e11d48"></span><span>🚨 ATTACK BLOCKED & QUARANTINED</span>';
    }
    if (alertBanner) alertBanner.style.display = 'flex';
    if (alertBadge) alertBadge.textContent = `${result.primaryThreat?.severity || 'CRITICAL'} • ${result.threatScore} CVSS • ${result.confidencePct}% Confidence`;
    if (alertDetail) {
      const neuralProbText = result.neuralInference ? ` | 🧠 Neural DL Probability: <strong>${(result.neuralInference.probability * 100).toFixed(1)}%</strong>` : '';
      alertDetail.innerHTML = `
        <strong>Matched Threat:</strong> ${esc(result.primaryThreat?.name || 'Prompt Injection')} (${esc(result.primaryThreat?.owasp || 'OWASP-LLM01')})${neuralProbText}<br>
        <strong>Detection Reason:</strong> ${esc(result.detectedThreats[0]?.detectionReason || '')}<br>
        <strong>Interception Action:</strong> ${esc(result.actionTaken)} — Security validation forced ON; safety policies locked.<br>
        <strong>Quarantined Snippet:</strong> <code>"${esc(result.detectedThreats[0]?.matchedPayload || '')}"</code>
      `;
    }
    if (tabBadge) {
      tabBadge.textContent = String(result.detectedThreats.length);
      tabBadge.style.display = 'inline-block';
    }
    showToast(`🚨 AAISecShield: Blocked ${result.primaryThreat?.name || 'Prompt Injection'} (CVSS ${result.threatScore})`);
  } else {
    if (heroCard) heroCard.className = 'aai-hero-card';
    if (statusPill) {
      statusPill.className = 'aai-status-pill armed';
      statusPill.innerHTML = '<span class="live-dot" style="background:#16a34a"></span><span>ARMED & GUARDING</span>';
    }
    if (alertBanner) alertBanner.style.display = 'none';
    if (tabBadge) tabBadge.style.display = 'none';
  }

  // Update Forensic Audit Log Table
  const auditBody = document.getElementById('aaiAuditLogBody');
  const logCount = document.getElementById('aaiLogCount');
  if (auditBody && AAISecShield.auditLog.length > 0) {
    if (logCount) logCount.textContent = `${AAISecShield.auditLog.length} incident(s)`;
    auditBody.innerHTML = AAISecShield.auditLog.map(entry => `
      <tr>
        <td style="font-family:'Space Mono',monospace;color:var(--text-dim)">${esc(entry.timestamp)}</td>
        <td><code>${esc(entry.id)}</code></td>
        <td style="font-weight:700;color:var(--text-bright)">${esc(entry.primaryThreat)}</td>
        <td><span class="aai-pill-badge high">${esc(entry.owaspRef)}</span></td>
        <td><span class="aai-pill-badge crit">${entry.threatScore.toFixed(1)}</span></td>
        <td><strong>${entry.confidence}%</strong></td>
        <td><span class="aai-pill-badge blocked">BLOCKED</span></td>
      </tr>
    `).join('');
  }
}

function launchAAIAttack(scenarioId) {
  if (typeof AAISecShield === 'undefined') return;
  const sc = AAISecShield.ATTACK_SCENARIOS.find(s => s.id === scenarioId);
  if (!sc || !codeInput) return;

  codeInput.value = sc.codeSnippet;
  updateLineNums();
  switchTab('aai-shield');
  runCompiler();
  showToast(`⚡ Simulated AAI Attack: ${sc.name}`);
}

function loadAAIAttackPreset(scenarioId) {
  launchAAIAttack(scenarioId);
}

// ════════════════════════════════════════════════════
//  AAI DEEP LEARNING MODEL TRAINING & VISUALIZATION
// ════════════════════════════════════════════════════
let aaiTrainingHistory = [];
let aaiChartInitialized = false;

function initAAILossChartIfNeeded() {
  if (aaiChartInitialized) return;
  // Baseline training curve display (Epochs 1-15 convergence)
  const baseline = [
    { epoch: 1, trainLoss: 0.6931, valLoss: 0.6850, valAcc: 75.0 },
    { epoch: 2, trainLoss: 0.5840, valLoss: 0.5620, valAcc: 87.5 },
    { epoch: 3, trainLoss: 0.4920, valLoss: 0.4710, valAcc: 87.5 },
    { epoch: 4, trainLoss: 0.4150, valLoss: 0.3980, valAcc: 100.0 },
    { epoch: 5, trainLoss: 0.3520, valLoss: 0.3390, valAcc: 100.0 },
    { epoch: 6, trainLoss: 0.2990, valLoss: 0.2880, valAcc: 100.0 },
    { epoch: 7, trainLoss: 0.2540, valLoss: 0.2450, valAcc: 100.0 },
    { epoch: 8, trainLoss: 0.2180, valLoss: 0.2110, valAcc: 100.0 },
    { epoch: 9, trainLoss: 0.1880, valLoss: 0.1820, valAcc: 100.0 },
    { epoch: 10, trainLoss: 0.1630, valLoss: 0.1580, valAcc: 100.0 },
    { epoch: 11, trainLoss: 0.1420, valLoss: 0.1380, valAcc: 100.0 },
    { epoch: 12, trainLoss: 0.1240, valLoss: 0.1210, valAcc: 100.0 },
    { epoch: 13, trainLoss: 0.1080, valLoss: 0.1060, valAcc: 100.0 },
    { epoch: 14, trainLoss: 0.0950, valLoss: 0.0980, valAcc: 100.0 },
    { epoch: 15, trainLoss: 0.0842, valLoss: 0.0915, valAcc: 100.0 }
  ];
  aaiTrainingHistory = baseline;
  drawAAILossChart(baseline, 15);
  aaiChartInitialized = true;
}

async function startAAINeuralTraining() {
  if (typeof AAISecShield === 'undefined') return;

  const btnTrain = document.getElementById('btnTrainAAI');
  const epochsInput = document.getElementById('dlEpochs');
  const lrInput = document.getElementById('dlLr');
  const logBox = document.getElementById('dlTrainingLog');
  const accSpan = document.getElementById('dlFinalAcc');

  const epochs = Math.max(5, Math.min(50, parseInt(epochsInput?.value || '15', 10)));
  const lr = Math.max(0.01, Math.min(2.0, parseFloat(lrInput?.value || '0.5')));

  if (btnTrain) {
    btnTrain.disabled = true;
    btnTrain.textContent = '⏳ Training in Progress...';
  }
  if (logBox) {
    const nTrain = AAISecShield?.SHIELD_DATASET?.train?.length || 80;
    const nVal = AAISecShield?.SHIELD_DATASET?.val?.length || 20;
    logBox.textContent = `[DL ENGINE] Initializing Stochastic Gradient Descent...\n` +
      `[DATASET] ${nTrain} Train Samples, ${nVal} Validation Samples (${nTrain + nVal} Benchmark Vectors)\n` +
      `[HYPERPARAMS] Epochs: ${epochs}, Learning Rate: ${lr}, Optimizer: SGD (BCE Loss)\n` +
      `----------------------------------------\n`;
  }

  aaiTrainingHistory = [];

  try {
    await AAISecShield.trainNeuralModel(epochs, lr, (stat) => {
      aaiTrainingHistory.push(stat);
      if (logBox) {
        logBox.textContent += `Epoch ${String(stat.epoch).padStart(2, '0')}/${epochs} | Loss: ${stat.trainLoss.toFixed(4)} | ValLoss: ${stat.valLoss.toFixed(4)} | ValAcc: ${stat.valAcc}%\n`;
        logBox.scrollTop = logBox.scrollHeight;
      }
      if (accSpan) {
        accSpan.textContent = `Val Accuracy: ${stat.valAcc}% (Loss: ${stat.valLoss.toFixed(4)})`;
      }
      drawAAILossChart(aaiTrainingHistory, epochs);
    });

    showToast(`🧠 AAI Neural Model trained across ${epochs} epochs! Weights converged.`);
  } catch (err) {
    console.error('Training error:', err);
    showToast(`⚠️ Training error: ${err.message}`);
  } finally {
    if (btnTrain) {
      btnTrain.disabled = false;
      btnTrain.textContent = '▶ Retrain Neural Model';
    }
  }
}

function exportAAIModelWeights() {
  if (typeof AAISecShield === 'undefined') return;
  const weightsJson = AAISecShield.exportModelWeights();
  const blob = new Blob([weightsJson], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'aai_model_weights.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('💾 Exported model weights artifact: aai_model_weights.json');
}

function drawAAILossChart(history, maxEpochs = 15) {
  const canvas = document.getElementById('aaiLossCanvas');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  // Background
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, w, h);

  // Grid lines
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
  ctx.lineWidth = 1;
  const padLeft = 45;
  const padBottom = 26;
  const padTop = 15;
  const padRight = 15;
  const plotW = w - padLeft - padRight;
  const plotH = h - padTop - padBottom;

  for (let i = 0; i <= 4; i++) {
    const y = padTop + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(w - padRight, y);
    ctx.stroke();

    // Y Axis labels (Loss scale 0.0 to 1.0)
    ctx.fillStyle = '#64748b';
    ctx.font = '9px monospace';
    ctx.textAlign = 'right';
    const val = (1.0 - (i * 0.25)).toFixed(2);
    ctx.fillText(val, padLeft - 6, y + 3);
  }

  // Draw legend
  ctx.fillStyle = '#a855f7';
  ctx.fillRect(w - 185, 10, 10, 3);
  ctx.fillStyle = '#cbd5e1';
  ctx.font = '10px monospace';
  ctx.textAlign = 'left';
  ctx.fillText('Train Loss (BCE)', w - 170, 14);

  ctx.fillStyle = '#38bdf8';
  ctx.fillRect(w - 75, 10, 10, 3);
  ctx.fillStyle = '#cbd5e1';
  ctx.fillText('Val Loss', w - 60, 14);

  if (!history || history.length === 0) return;

  const total = Math.max(history.length, maxEpochs);

  // Helper coordinate mapper
  const getX = (idx) => padLeft + (idx / Math.max(1, total - 1)) * plotW;
  const getY = (val) => padTop + Math.max(0, Math.min(plotH, (1 - Math.min(1.0, val)) * plotH));

  // Plot Train Loss (Violet)
  ctx.strokeStyle = '#a855f7';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  history.forEach((pt, i) => {
    const x = getX(i);
    const y = getY(pt.trainLoss);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Plot Val Loss (Cyan)
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2;
  ctx.beginPath();
  history.forEach((pt, i) => {
    const x = getX(i);
    const y = getY(pt.valLoss);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Points on latest epoch
  if (history.length > 0) {
    const last = history[history.length - 1];
    const lastX = getX(history.length - 1);

    ctx.fillStyle = '#a855f7';
    ctx.beginPath();
    ctx.arc(lastX, getY(last.trainLoss), 4, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = '#38bdf8';
    ctx.beginPath();
    ctx.arc(lastX, getY(last.valLoss), 4, 0, Math.PI * 2);
    ctx.fill();
  }

  // X Axis Epoch numbers
  ctx.fillStyle = '#64748b';
  ctx.font = '9px monospace';
  ctx.textAlign = 'center';
  ctx.fillText(`Epoch 1`, padLeft, h - 8);
  ctx.fillText(`Epoch ${total}`, w - padRight, h - 8);
}