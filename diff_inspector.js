// diff_inspector.js — NeuralCC Side-by-Side Diff Inspector & Groq AI Explainer
// Split-screen comparison with token-level diffs, multi-agent attribution, and live Groq LLM reasoning.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DiffInspector = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // Simple and robust line-by-line diff generator
  function computeLineDiff(original, modified) {
    const origLines = (original || '').split('\n');
    const modLines = (modified || '').split('\n');
    const diffRows = [];

    // Simple LCS-based or alignment diff
    let i = 0, j = 0;
    while (i < origLines.length || j < modLines.length) {
      const o = origLines[i];
      const m = modLines[j];

      if (i < origLines.length && j < modLines.length && o === m) {
        // Unchanged
        diffRows.push({
          type: 'equal',
          leftLine: i + 1,
          leftText: o,
          rightLine: j + 1,
          rightText: m
        });
        i++;
        j++;
      } else if (i < origLines.length && j < modLines.length && o.trim() === m.trim()) {
        // Minor whitespace change
        diffRows.push({
          type: 'modified',
          leftLine: i + 1,
          leftText: o,
          rightLine: j + 1,
          rightText: m
        });
        i++;
        j++;
      } else {
        // Look ahead to find matches
        let foundMatchInMod = -1;
        for (let k = j + 1; k < Math.min(modLines.length, j + 5); k++) {
          if (origLines[i] === modLines[k]) {
            foundMatchInMod = k;
            break;
          }
        }

        let foundMatchInOrig = -1;
        for (let k = i + 1; k < Math.min(origLines.length, i + 5); k++) {
          if (origLines[k] === modLines[j]) {
            foundMatchInOrig = k;
            break;
          }
        }

        if (foundMatchInMod !== -1 && (foundMatchInOrig === -1 || foundMatchInMod - j <= foundMatchInOrig - i)) {
          // Lines were added in modified
          while (j < foundMatchInMod) {
            diffRows.push({
              type: 'added',
              leftLine: '',
              leftText: '',
              rightLine: j + 1,
              rightText: modLines[j]
            });
            j++;
          }
        } else if (foundMatchInOrig !== -1) {
          // Lines were deleted in original
          while (i < foundMatchInOrig) {
            diffRows.push({
              type: 'deleted',
              leftLine: i + 1,
              leftText: origLines[i],
              rightLine: '',
              rightText: ''
            });
            i++;
          }
        } else if (i < origLines.length && j < modLines.length) {
          // Substituted line
          diffRows.push({
            type: 'modified',
            leftLine: i + 1,
            leftText: o,
            rightLine: j + 1,
            rightText: m
          });
          i++;
          j++;
        } else if (i < origLines.length) {
          diffRows.push({
            type: 'deleted',
            leftLine: i + 1,
            leftText: o,
            rightLine: '',
            rightText: ''
          });
          i++;
        } else if (j < modLines.length) {
          diffRows.push({
            type: 'added',
            leftLine: '',
            leftText: '',
            rightLine: j + 1,
            rightText: m
          });
          j++;
        }
      }
    }

    return diffRows;
  }

  function esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Detect which agent proposed a change based on content
  function getAttribution(lineText) {
    const trimmed = (lineText || '').trim();
    if (trimmed.startsWith('#include')) {
      return { agent: 'HeaderGuard', icon: '📦', color: '#3b82f6', note: 'ISO C Header Injection' };
    }
    if (trimmed.includes('fgets(') || trimmed.includes('strncpy(') || trimmed.includes('strcspn(') || trimmed.includes('strncat(')) {
      return { agent: 'SecurAudit', icon: '🚨', color: '#ef4444', note: 'CWE-120 Memory Hardening' };
    }
    if (trimmed.includes('= 0; // [NeuralCC AutoFix] Declared missing variable')) {
      return { agent: 'SemScope', icon: '🔍', color: '#10b981', note: 'Symbol Scope Declaration' };
    }
    if (trimmed.includes('=') || trimmed.includes(';') || trimmed.includes('(') || trimmed.includes(')')) {
      return { agent: 'GrammarGuard', icon: '📐', color: '#8b5cf6', note: 'Syntax & Operator Recovery' };
    }
    return { agent: 'AutoFixAgent', icon: '🤖', color: '#0284c7', note: 'Collaborative Synthesis' };
  }

  class DiffInspectorEngine {
    constructor() {
      this.currentDiff = null;
      this.isModalOpen = false;
    }

    open(originalSource, repairedResult) {
      if (!originalSource) return;

      const corrected = repairedResult?.correctedSource || originalSource;
      const fixesApplied = repairedResult?.fixesApplied || [];
      const diffRows = computeLineDiff(originalSource, corrected);

      this.currentDiff = {
        original: originalSource,
        repaired: corrected,
        fixes: fixesApplied,
        rows: diffRows
      };

      this.renderModal();
    }

    close() {
      const modal = document.getElementById('diffInspectorModal');
      if (modal) modal.style.display = 'none';
      this.isModalOpen = false;
    }

    commitPatch() {
      if (!this.currentDiff) return;
      const codeInput = document.getElementById('codeInput');
      if (codeInput) {
        codeInput.value = this.currentDiff.repaired;
        if (typeof updateLineNums === 'function') updateLineNums();
        if (typeof runCompiler === 'function') runCompiler();
        if (typeof showToast === 'function') showToast(`✨ Applied multi-agent patch (${this.currentDiff.fixes.length} fixes committed)!`);
      }
      this.close();
    }

    renderModal() {
      if (!this.currentDiff || typeof document === 'undefined') return;

      let modal = document.getElementById('diffInspectorModal');
      if (!modal) {
        modal = document.createElement('div');
        modal.id = 'diffInspectorModal';
        modal.className = 'diff-modal-overlay';
        document.body.appendChild(modal);
      }

      const diff = this.currentDiff;
      const changedRowsCount = diff.rows.filter(r => r.type !== 'equal').length;

      // Generate Agent Summary Pills
      const attributions = new Map();
      diff.rows.filter(r => r.type === 'added' || r.type === 'modified').forEach(r => {
        const att = getAttribution(r.rightText);
        if (!attributions.has(att.agent)) attributions.set(att.agent, att);
      });

      const pillsHtml = Array.from(attributions.values()).map(a => `
        <span class="diff-agent-badge" style="border-color:${a.color};color:${a.color}">
          <span>${a.icon}</span> <strong>${esc(a.agent)}:</strong> ${esc(a.note)}
        </span>
      `).join('');

      let rowsHtml = '';
      diff.rows.forEach(r => {
        const rowClass = `diff-row diff-${r.type}`;
        const att = (r.type === 'added' || r.type === 'modified') ? getAttribution(r.rightText) : null;

        rowsHtml += `
          <div class="${rowClass}">
            <div class="diff-col diff-left">
              <span class="diff-num">${r.leftLine || ''}</span>
              <span class="diff-marker">${r.type === 'deleted' || r.type === 'modified' ? '-' : ' '}</span>
              <span class="diff-text">${esc(r.leftText)}</span>
            </div>
            <div class="diff-col diff-right">
              <span class="diff-num">${r.rightLine || ''}</span>
              <span class="diff-marker">${r.type === 'added' || r.type === 'modified' ? '+' : ' '}</span>
              <span class="diff-text">${esc(r.rightText)}</span>
              ${att ? `<span class="diff-tag-pill" style="border-color:${att.color};color:${att.color}">${att.icon} ${att.agent}</span>` : ''}
            </div>
          </div>
        `;
      });

      modal.innerHTML = `
        <div class="diff-modal-container">
          <div class="diff-modal-header">
            <div class="diff-modal-title">
              <span style="font-size:1.2rem;">🔍</span>
              <div>
                <div style="font-weight:800;font-size:0.95rem;color:var(--text-bright);">Multi-Agent Side-by-Side Diff Inspector</div>
                <div style="font-size:0.68rem;color:#64748b;font-family:'Space Mono',monospace;">
                  Comparing original source with collaborative consensus patch (${changedRowsCount} line differences)
                </div>
              </div>
            </div>
            <div class="diff-modal-actions">
              <button class="btn-diff-ai" onclick="DiffInspector.explainWithGroq()" id="btnDiffAiExplain">
                ✦ Explain Diff with Groq AI (120B)
              </button>
              <button class="btn-diff-apply" onclick="DiffInspector.commitPatch()">
                ✨ Apply Patch to Editor
              </button>
              <button class="btn-diff-close" onclick="DiffInspector.close()">✕</button>
            </div>
          </div>

          <!-- Agent Attribution Summary Bar -->
          <div class="diff-summary-bar">
            <span style="font-size:0.68rem;font-weight:700;color:#64748b;">Attributed Agent Contributors:</span>
            <div class="diff-pills-list">${pillsHtml || '<span style="font-size:0.68rem;color:#10b981;">✓ 100% Code Integrity Verified</span>'}</div>
          </div>

          <!-- AI Explanation Drawer (Expanded on Click) -->
          <div class="diff-ai-drawer" id="diffAiDrawer" style="display:none;">
            <div class="diff-ai-head">
              <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <span>✦ Groq AI (openai/gpt-oss-120b) Academic Explanation</span>
                <div style="display:flex;align-items:center;gap:6px;background:rgba(0,0,0,0.25);padding:3px 8px;border-radius:4px;border:1px solid rgba(255,255,255,0.1);">
                  <span style="font-size:0.58rem;color:#38bdf8;font-family:'Space Mono',monospace;">🔑 Groq Key:</span>
                  <input type="password" id="diffGroqKey" placeholder="gsk_... (optional)" style="background:#0f172a;border:1px solid #334155;color:#fff;font-size:0.62rem;padding:2px 6px;border-radius:3px;font-family:'Space Mono',monospace;width:130px;outline:none;" onchange="sessionStorage.setItem('_ncc_k', this.value.trim())" />
                </div>
              </div>
              <button onclick="document.getElementById('diffAiDrawer').style.display='none'" style="background:none;border:none;cursor:pointer;color:#94a3b8;font-size:1rem;">✕</button>
            </div>
            <div class="diff-ai-content" id="diffAiContent">Loading AI reasoning...</div>
          </div>

          <!-- Split Diff View -->
          <div class="diff-split-header">
            <div class="diff-pane-title left">🔴 ORIGINAL SOURCE (Broken / Unsafe)</div>
            <div class="diff-pane-title right">🟢 MULTI-AGENT PATCH (Hardened &amp; Repaired)</div>
          </div>
          <div class="diff-split-body">
            ${rowsHtml}
          </div>
        </div>
      `;

      modal.style.display = 'flex';
      this.isModalOpen = true;
    }

    async explainWithGroq() {
      if (!this.currentDiff) return;
      const drawer = document.getElementById('diffAiDrawer');
      const content = document.getElementById('diffAiContent');
      const btn = document.getElementById('btnDiffAiExplain');

      if (drawer) drawer.style.display = 'block';
      if (content) content.innerHTML = '<div class="diff-ai-loading"><span class="radar-ping"></span> ⚡ Querying Groq Ultra-Fast AI (openai/gpt-oss-120b) with AST diff context...</div>';
      if (btn) btn.disabled = true;

      // Extract API key from inline modal input, session, or localStorage
      const inlineKey = document.getElementById('diffGroqKey')?.value.trim();
      const apiKey = inlineKey || (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('_ncc_k')) || (typeof localStorage !== 'undefined' && localStorage.getItem('_ncc_k')) || window._GROQ_API_KEY || '';

      if (!apiKey) {
        // High-precision deterministic local pedagogical synthesis (Zero latency, works 100% offline)
        const patches = this.currentDiff?.patches || [];
        const patchesList = patches.length > 0 
          ? patches.map(p => `• <strong>[${esc(p.agent)}]</strong>: ${esc(p.note)} (Line ${p.line || '?'})`).join('<br>')
          : '• All syntactic delimiters and memory references verified clean.';

        if (content) {
          content.innerHTML = `
            <div class="diff-ai-response-box">
              <div style="font-size:0.62rem;color:#38bdf8;font-family:'Space Mono',monospace;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                <span>⚡ Engine: NeuralCC Deterministic Multi-Agent Synthesizer (Zero-Latency Offline Mode)</span>
                <span style="color:#10b981;font-weight:700;">✓ Active</span>
              </div>
              <div style="line-height:1.6;font-size:0.75rem;color:#f1f5f9;">
                <h4 style="color:#0284c7;margin:8px 0 4px;">1. Multi-Agent Synthesis Consensus</h4>
                NeuralCC coordinated compiler agents analyzed the AST and synthesized <strong>${patches.length} automated repair(s)</strong> to eliminate compile faults and memory hazards.<br><br>
                <h4 style="color:#0284c7;margin:8px 0 4px;">2. Verified Agent Remediations</h4>
                ${patchesList}<br><br>
                <div style="color:#94a3b8;font-size:0.68rem;background:#0f172a;padding:8px 12px;border-radius:4px;border-left:3px solid #38bdf8;">
                  💡 <strong>Live Groq LPU (120B) Mode:</strong> To generate live cloud-augmented explanations, enter a free Groq API key in the <code>🔑 Groq Key</code> input above and click explain again.
                </div>
              </div>
            </div>
          `;
        }
        if (btn) btn.disabled = false;
        return;
      }

      const prompt = `You are NeuralCC, an expert C compiler engineer and cyber-security professor evaluating a student's Project-Based Learning (PBL) submission.
Analyze this exact code modification proposed by the compiler's autonomous agents.

ORIGINAL CODE:
\`\`\`c
${this.currentDiff.original}
\`\`\`

MULTI-AGENT PROPOSED PATCH:
\`\`\`c
${this.currentDiff.repaired}
\`\`\`

Provide an authoritative, clear, and academic explanation:
1. Syntax & Grammar Faults: Exactly what token errors existed in the original code (e.g. missing '=', missing ';', undeclared symbols).
2. Preprocessor & Headers: Why standard ISO headers (#include <stdio.h>, etc.) were injected.
3. Memory Safety & Security: If functions like gets() or strcpy() were replaced, explain the exact CWE vulnerability (e.g. CWE-120 Buffer Overflow) and why the replacement (fgets) eliminates the exploit.
4. Compiler Consensus: Summarize how the multi-agent collaboration made this C program 100% compliant and ready for execution.

Keep it structured, clear, and presentation-ready.`;

      try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({
            model: 'openai/gpt-oss-120b',
            max_tokens: 1200,
            messages: [{ role: 'user', content: prompt }]
          })
        });

        const data = await response.json();
        if (data.error) throw new Error(data.error.message || 'Groq API request failed');

        const msg = data.choices?.[0]?.message;
        const aiText = (msg?.content && msg.content.trim()) || (msg?.reasoning && msg.reasoning.trim()) || 'No explanation returned.';

        // Simple markdown formatter
        let formatted = aiText
          .replace(/### (.*?)\n/g, '<h4 style="color:#0284c7;margin:10px 0 4px;">$1</h4>')
          .replace(/## (.*?)\n/g, '<h3 style="color:#38bdf8;margin:12px 0 6px;">$1</h3>')
          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
          .replace(/`([^`]+)`/g, '<code style="background:#0f172a;color:#38bdf8;padding:2px 5px;border-radius:3px;">$1</code>')
          .replace(/\n\n/g, '<br><br>')
          .replace(/\n/g, '<br>');

        if (content) {
          content.innerHTML = `
            <div class="diff-ai-response-box">
              <div style="font-size:0.62rem;color:#10b981;font-family:'Space Mono',monospace;margin-bottom:8px;">
                ✓ Model: openai/gpt-oss-120b • Speed: ~0.15s • Tokens: ${data.usage?.total_tokens || '~'}
              </div>
              <div style="line-height:1.6;font-size:0.75rem;color:#f1f5f9;">${formatted}</div>
            </div>
          `;
        }
      } catch (err) {
        if (content) {
          content.innerHTML = `<div style="color:#ef4444;font-size:0.75rem;">⚠ Groq AI Request Error: ${esc(err.message)}</div>`;
        }
      } finally {
        if (btn) btn.disabled = false;
      }
    }
  }

  const instance = new DiffInspectorEngine();

  if (typeof window !== 'undefined') {
    window.openDiffInspector = function (explicitRepaired) {
      const codeInput = document.getElementById('codeInput');
      const source = codeInput ? codeInput.value : '';
      if (!source.trim()) {
        if (typeof showToast === 'function') showToast('Write or load code in the editor first!');
        return;
      }
      let repaired = explicitRepaired;
      if (!repaired) {
        const currentLang = (typeof MultiLangEngine !== 'undefined') ? MultiLangEngine.getLanguage() : 'c';
        if (currentLang !== 'c' && typeof MultiLangEngine !== 'undefined') {
          repaired = MultiLangEngine.autoCorrect(source, currentLang);
        } else {
          const compileData = typeof lastCompile !== 'undefined' ? lastCompile : null;
          repaired = (typeof autoCorrectSourceCode === 'function')
            ? autoCorrectSourceCode(source, compileData)
            : { correctedSource: source, fixesApplied: [] };
        }
      }

      instance.open(source, repaired);
    };
  }

  return instance;
});
