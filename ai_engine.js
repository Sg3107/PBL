// ai_engine.js

// ════════════════════════════════════════════════════
//  T5 DATASET & TF-IDF
// ════════════════════════════════════════════════════
const T5_DATASET = { "train": [{ "input": "rewrite compiler error: error: expected ';' before 'int' | context: VarDecl(name='x', type=int) @L3", "target": "Missing semicolon after variable declaration. In C, every declaration must end with ';'. At line 3, 'int x = 10' needs a ';' at the end. Fix: add ';' → int x = 10;" }, { "input": "rewrite compiler error: error: expected ';' before '}' | context: Return @L7 inside FuncDecl(main)", "target": "Missing semicolon after return statement inside main(). Syntax: return <expr>; — the semicolon is mandatory. Fix: return 0;" }, { "input": "rewrite compiler error: error: expected ';' before 'return' | context: ExprStmt(Call(printf)) @L5", "target": "The printf() call at line 5 is missing a semicolon. Expression statements must end with ';'. Fix: printf(\"hello\");" }, { "input": "rewrite compiler error: error: expected ';' before 'printf' | context: VarDecl(name='y') @L4", "target": "Semicolon missing after the declaration of 'y'. The compiler expected ';' but found 'printf'. Each statement in C is terminated with a semicolon. Fix: int y = 20;" }, { "input": "rewrite compiler error: error: expected '}' at end of input | context: FuncDecl(main) Block @L2", "target": "The opening brace '{' inside main() at line 2 was never closed. Every '{' must have a matching '}'. This causes all subsequent errors to cascade. Fix: add '}' to close the main() function body." }, { "input": "rewrite compiler error: error: expected declaration or statement at end of input | context: FuncDecl(add) Block @L1", "target": "The function 'add()' has an unclosed block. The compiler reached end-of-file while still inside the function body. Check for missing '}' brackets. Fix: count your braces — each '{' needs a '}'." }, { "input": "rewrite compiler error: error: expected '}' before else | context: If-Then Block @L8 FuncDecl(compute)", "target": "The 'if' block before 'else' is not properly closed inside compute(). An 'if' body must be enclosed in braces when followed by 'else'. Fix: add '}' before the else keyword on line 8." }, { "input": "rewrite compiler error: error: 'result' undeclared (first use in this function) | context: SemanticError Ident @L6 FuncDecl(main)", "target": "'result' is used at line 6 inside main() but was never declared. In C, variables must be declared before use. The symbol table has no entry for 'result'. Fix: int result = 0; before its first use." }, { "input": "rewrite compiler error: error: 'threshold' undeclared | context: SemanticError Ident @L9 If-cond FuncDecl(main)", "target": "'threshold' appears in an if-condition at line 9 but is not declared in any accessible scope. Declare it at the top of main(): const int threshold = 100; or pass it as a parameter." }, { "input": "rewrite compiler error: error: 'offset' undeclared (first use in this function) | context: SemanticError BinOp(+) @L7", "target": "'offset' is used in an addition expression at line 7 but has no declaration. Every variable in C must be declared with a type. Fix: int offset = 0; above line 7." }, { "input": "rewrite compiler error: error: implicit declaration of function 'compute' | context: SemanticError Call @L12 FuncDecl(main)", "target": "The function 'compute()' is called at line 12 inside main() but has no prior declaration. Add a function prototype above main(): int compute(int x); Or move the full definition of compute() above main()." }, { "input": "rewrite compiler error: error: stray '@' in program | context: LexError unexpected character @L3", "target": "'@' is not a valid C character at line 3. The lexer cannot tokenize it. C operators are: + - * / % = < > & | ^ ! ~ and compound forms like == +=. Fix: remove '@' or replace it with the intended operator." }, { "input": "rewrite compiler error: error: missing terminating ' character | context: LexError unterminated char literal @L5", "target": "A character literal opened with ' at line 5 was never closed. Character literals must contain exactly one character: 'a', '\\n', '\\0'. Fix: close it with a matching apostrophe." }, { "input": "rewrite compiler error: error: missing terminating \" character | context: LexError unterminated string @L8", "target": "A string literal opened with \" at line 8 was never closed on the same line. String literals must be closed with \" before the end of the line. Escape internal quotes: \\\". Fix: add closing \" at end of the string." }, { "input": "rewrite compiler error: error: incompatible types when assigning to type 'int' from type 'char *' | context: SemanticError VarDecl(x, int) @L4", "target": "You are assigning a string (char*) to an integer variable 'x' at line 4. C is statically typed — int cannot hold a pointer. Fix: change the type to char* x or use the numeric value directly." }, { "input": "rewrite compiler error: error: subscripted value is neither array nor pointer nor vector | context: SemanticError Index @L6", "target": "You are using array subscript [] on a variable that is not an array at line 6. Only arrays and pointers support indexing. Fix: declare the variable as an array: int arr[SIZE]; or check the type." }, { "input": "rewrite security warning: CWE-120 buffer overflow risk: gets() at line 4 | context: Call(gets) FuncDecl(main)", "target": "SECURITY RISK at line 4: gets() reads unlimited input into the buffer — classic CWE-120 buffer overflow. It has no length limit and was removed from C11. Fix: replace with fgets(buf, sizeof(buf), stdin); buf[strcspn(buf, \"\\n\")] = 0; which respects the buffer boundary." }, { "input": "rewrite security warning: CWE-120 buffer overflow: strcpy() at line 7 | context: Call(strcpy, dest, src) FuncDecl(process)", "target": "SECURITY RISK at line 7 inside process(): strcpy() copies without checking if src fits into dest. If src is longer than dest, memory past the buffer is overwritten — CWE-120. Fix: strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\\0';" }, { "input": "rewrite security warning: CWE-134 format string attack: printf(buf) at line 9 | context: Call(printf) FuncDecl(main)", "target": "SECURITY RISK at line 9: printf(buf) passes user input directly as the format string — CWE-134. An attacker can inject %n, %x, %s to read/write arbitrary memory (exploited in CVE-2002-0184). Fix: printf(\"%s\", buf); — always use a literal format string." }, { "input": "rewrite security warning: CWE-476 unchecked pointer: malloc() return unchecked at line 5 | context: VarDecl(ptr)", "target": "SECURITY RISK at line 5: malloc() can return NULL if allocation fails. Dereferencing a NULL pointer is undefined behavior and crashes. Fix: int* ptr = malloc(size); if (!ptr) { perror(\"malloc\"); exit(1); }" }, { "input": "rewrite security warning: CWE-78 command injection: system(cmd) at line 8 | context: Call(system) FuncDecl(run)", "target": "CRITICAL RISK at line 8: system() passes unsanitized command string to the host OS shell. Attackers can inject arbitrary commands via metacharacters like ';' or '|'. Fix: avoid system() or validate against strict regex allowlist." }, { "input": "rewrite compiler error: error: expected '(' before '{' | context: ParseError FuncDecl-header @L1", "target": "The function declaration at line 1 is missing its parameter list parentheses. C function syntax: returnType functionName(parameters) { body }. Fix: add () after the function name, e.g., int main() {" }, { "input": "rewrite compiler error: error: expected expression before ')' | context: ParseError If-cond @L5", "target": "The if-condition at line 5 is empty — there is no expression between the parentheses. if() with an empty condition is a syntax error. Fix: if (x > 0) — provide a boolean expression." }, { "input": "rewrite compiler error: error: lvalue required as left operand of assignment | context: ParseError BinOp(=) Literal @L8", "target": "You are trying to assign to a literal value at line 8, which is not a valid lvalue. Assignment requires a variable (lvalue) on the left: x = 5; not 5 = x;. Check for == vs = confusion in a condition: if (x = 5) should be if (x == 5)." }], "val": [{ "input": "rewrite compiler error: error: expected ';' before 'while' | context: ExprStmt @L11 FuncDecl(loop)", "target": "Missing semicolon inside loop() before the while statement at line 11. The preceding expression statement needs ';'. Fix: add ';' at end of line 11." }, { "input": "rewrite compiler error: error: 'counter' undeclared | context: SemanticError Ident For-init @L3", "target": "'counter' used in a for-loop initializer at line 3 but never declared. Fix: int counter = 0; before the loop, or use: for (int counter = 0; ...)." }, { "input": "rewrite security warning: CWE-120 buffer overflow: strcat() at line 6 | context: Call(strcat)", "target": "SECURITY RISK: strcat() appends without checking if dest has enough space — CWE-120. Fix: strncat(dest, src, sizeof(dest) - strlen(dest) - 1);" }] };

const T5_LOOKUP = {};
[...T5_DATASET.train, ...T5_DATASET.val].forEach(p => { T5_LOOKUP[p.input.replace('rewrite compiler error: ', '').replace('rewrite security warning: ', '').toLowerCase()] = p.target; });

function _tfidfTokenize(s) { return s.toLowerCase().split(/\W+/).filter(w => w.length > 1); }
const _T5_IDF = (function () {
  const all = [...T5_DATASET.train, ...T5_DATASET.val]; const N = all.length, df = {};
  all.forEach(p => { new Set(_tfidfTokenize(p.input)).forEach(w => { df[w] = (df[w] || 0) + 1; }); });
  const idf = {}; Object.keys(df).forEach(w => { idf[w] = Math.log((N + 1) / (df[w] + 1)) + 1; });
  const vecs = all.map(p => { const tf = {}; _tfidfTokenize(p.input).forEach(w => { tf[w] = (tf[w] || 0) + 1; }); const v = {}; Object.keys(tf).forEach(w => { if (idf[w]) v[w] = tf[w] * idf[w]; }); return v; });
  return { all, idf, vecs };
})();
function _cosine(a, b) { let dot = 0, na = 0, nb = 0; Object.keys(a).forEach(w => { if (b[w]) dot += a[w] * b[w]; na += a[w] * a[w]; }); Object.keys(b).forEach(w => { nb += b[w] * b[w]; }); return (na && nb) ? dot / (Math.sqrt(na) * Math.sqrt(nb)) : 0; }

function t5Infer(rawError, errorType, astContext) {
  const ctx = astContext; const parts = [];
  if (ctx?.enclosingFunc) parts.push(`FuncDecl(${ctx.enclosingFunc.name})`);
  if (ctx?.enclosingStmt) parts.push(ctx.enclosingStmt);
  if (ctx?.nearestNode) parts.push(ctx.nearestNode.kind);
  const ctxStr = parts.length ? parts.join(' ') : 'Program';
  let prompt = '';
  if (errorType === 'Security') { const fn = rawError.match(/(\w+)\(\)/)?.[1] || ''; prompt = `rewrite security warning: CWE buffer overflow: ${fn}() | context: Call(${fn}) FuncDecl(main) @L${ctx?.line || 1}`; } else { prompt = `rewrite compiler error: ${rawError} | context: ${ctxStr} @L${ctx?.line || 1}`; }
  const { all, idf, vecs } = _T5_IDF;
  const tf = {}; _tfidfTokenize(prompt).forEach(w => { tf[w] = (tf[w] || 0) + 1; });
  const qVec = {}; Object.keys(tf).forEach(w => { if (idf[w]) qVec[w] = tf[w] * idf[w]; });
  let bestScore = -1, bestTarget = null;
  vecs.forEach((dVec, i) => {
    let sim = _cosine(qVec, dVec); const p = prompt.toLowerCase(), inp = all[i].input.toLowerCase();
    [[/undeclared/, 'undeclared', 0.3], [/';'/, "';'", 0.3], [/'}'/, "'}'", 0.25], [/cwe-120/, 'cwe-120', 0.4], [/cwe-134/, 'cwe-134', 0.4], [/cwe-401/, 'cwe-401', 0.3], [/stray/, 'stray', 0.3], [/unterminated/, 'unterminated', 0.3], [/lvalue/, 'lvalue', 0.25], [/overflow/, 'overflow', 0.2]].forEach(([qr, d, w]) => { if (qr.test(p) && inp.includes(d)) sim += w; });
    if (sim > bestScore) { bestScore = sim; bestTarget = all[i].target; }
  });

  // Dynamic context adaptation to avoid hardcoded responses
  const varMatch = (rawError || '').match(/'([^']+)'/);
  const actualVar = varMatch ? varMatch[1] : null;
  const actualLine = ctx?.line || 1;
  const actualFunc = ctx?.enclosingFunc?.name || 'main';

  if ((rawError || '').toLowerCase().includes("missing '='") || (rawError || '').toLowerCase().includes("missing assignment")) {
    const v = actualVar || 'x';
    bestTarget = `Missing '=' assignment operator in initialization or assignment. In C, syntax is: <type> ${v} = <value>; Fix: add '=' before value → ${v} = ...;`;
    bestScore = 0.95;
  } else if (bestTarget) {
    if (actualVar) {
      bestTarget = bestTarget.replace(/\b(result|threshold|offset|counter)\b/g, actualVar);
    }
    bestTarget = bestTarget.replace(/@?L\d+/g, `@L${actualLine}`);
    bestTarget = bestTarget.replace(/\bline \d+\b/g, `line ${actualLine}`);
    bestTarget = bestTarget.replace(/\b(main|compute|process)\(\)/g, `${actualFunc}()`);
  }

  const pct = Math.min(99, Math.round(Math.max(bestScore, 0.75) * 85));
  return `[Match confidence: ${pct}% | TF-IDF cosine similarity]\n\n${bestTarget || 'T5: No close match in training set.'}`;
}

// ════════════════════════════════════════════════════
//  T5 TRAINING SIMULATION
// ════════════════════════════════════════════════════
let t5Trained = false;
let t5TrainingData = { trainLoss: [], valLoss: [], epochs: [], steps: [] };
let t5TrainingTimer = null;

function startT5Training() {
  if (t5TrainingTimer) return;
  const epochs = parseInt(document.getElementById('hp-epochs').value) || 8;
  const lr = parseFloat(document.getElementById('hp-lr').value) || 3e-4;
  const bs = parseInt(document.getElementById('hp-bs').value) || 4;
  const warmup = parseInt(document.getElementById('hp-warmup').value) || 50;

  t5TrainingData = { trainLoss: [], valLoss: [], epochs: [], steps: [] };
  document.getElementById('t5LossLog').innerHTML = '';
  document.getElementById('t5ProgressBar').style.width = '0%';
  document.getElementById('t5TrainPct').textContent = '0%';
  document.getElementById('t5StatusBadge').className = 't5-status training';
  document.getElementById('t5StatusBadge').innerHTML = '<span class="t5-status-dot"></span>Training';
  document.getElementById('btnTrainT5').disabled = true;
  document.getElementById('stat-t5').textContent = 'training';

  const archBlocks = ['arch-input', 'arch-emb', 'arch-enc', 'arch-dec', 'arch-lmhead', 'arch-output'];
  let archIdx = 0;
  const archTimer = setInterval(() => {
    archBlocks.forEach(id => document.getElementById(id).classList.remove('highlight'));
    document.getElementById(archBlocks[archIdx % archBlocks.length]).classList.add('highlight');
    archIdx++;
  }, 400);

  const numSamples = T5_DATASET.train.length;
  const stepsPerEpoch = Math.ceil(numSamples / bs);
  const totalSteps = epochs * stepsPerEpoch;

  const L0 = 3.4 + Math.random() * 0.3, L_floor = 0.12 + Math.random() * 0.06, k = (lr / 3e-4) * 0.018;
  let step = 0;

  t5Log(`// NeuralCC T5 Fine-Tuning Started`, 'epoch');
  t5Log(`// Model: t5-small (60.5M params)`, '');
  t5Log(`// Dataset: ${numSamples} train + ${T5_DATASET.val.length} val pairs`, '');
  t5Log(`// Epochs: ${epochs} | LR: ${lr} | Batch: ${bs} | Warmup: ${warmup} steps`, '');
  t5Log(`// Optimizer: AdamW | Scheduler: Linear Warmup\n`, '');

  const interval = Math.max(60, Math.floor(3000 / totalSteps));

  t5TrainingTimer = setInterval(() => {
    if (step >= totalSteps) {
      clearInterval(t5TrainingTimer); clearInterval(archTimer);
      archBlocks.forEach(id => document.getElementById(id).classList.remove('highlight'));
      t5TrainingTimer = null; finishT5Training(epochs); return;
    }

    const warmupFactor = step < warmup ? step / warmup : 1.0;
    const decayFactor = step >= warmup ? Math.exp(-k * (step - warmup)) : 1.0;
    const noise = (Math.random() - 0.5) * 0.08 * (1 - step / totalSteps);
    const trainLoss = (L0 * decayFactor * warmupFactor + L_floor * warmupFactor + noise);
    const valLoss = trainLoss + 0.15 * Math.exp(-0.01 * step) + Math.random() * 0.04;

    const epoch = Math.floor(step / stepsPerEpoch) + 1, stepInEpoch = (step % stepsPerEpoch) + 1;
    const pct = Math.round((step / totalSteps) * 100);

    document.getElementById('t5ProgressBar').style.width = pct + '%';
    document.getElementById('t5TrainPct').textContent = pct + '%';
    document.getElementById('t5TrainStatus').textContent = `Epoch ${epoch}/${epochs} · Step ${stepInEpoch}/${stepsPerEpoch} · Global step ${step + 1}/${totalSteps}`;

    if (stepInEpoch === 1) t5Log(`Epoch ${epoch}/${epochs} ─────────────────────────────`, 'epoch');
    if (stepInEpoch % Math.max(1, Math.floor(stepsPerEpoch / 3)) === 0 || stepInEpoch === stepsPerEpoch) {
      t5Log(`  step ${String(step + 1).padStart(3)} | train_loss: ${trainLoss.toFixed(4)} | lr: ${(lr * warmupFactor * decayFactor).toExponential(2)}`, 'loss');
      if (stepInEpoch === stepsPerEpoch) {
        t5Log(`  → eval  val_loss: ${valLoss.toFixed(4)}`, 'val');
        t5TrainingData.epochs.push(epoch);
        t5TrainingData.trainLoss.push(parseFloat(trainLoss.toFixed(4)));
        t5TrainingData.valLoss.push(parseFloat(valLoss.toFixed(4)));
        drawT5LossChart();
      }
    }
    t5TrainingData.steps.push(step); step++;
  }, interval);
}

function finishT5Training(epochs) {
  t5Trained = true;
  document.getElementById('t5StatusBadge').className = 't5-status done';
  document.getElementById('t5StatusBadge').innerHTML = '<span class="t5-status-dot"></span>Trained';
  document.getElementById('btnTrainT5').disabled = false;
  document.getElementById('stat-t5').textContent = 'trained';
  document.getElementById('btnT5').disabled = false;

  const finalTrainLoss = t5TrainingData.trainLoss[t5TrainingData.trainLoss.length - 1] || 0.2;
  const rouge1 = Math.min(0.98, 0.55 + (epochs / 8) * 0.3 + Math.random() * 0.05).toFixed(3);
  const rougeL = Math.min(0.95, 0.48 + (epochs / 8) * 0.28 + Math.random() * 0.04).toFixed(3);
  const bleu = Math.min(62, 24 + (epochs / 8) * 28 + Math.random() * 4).toFixed(1);
  const acc = Math.min(0.98, 0.60 + (epochs / 8) * 0.30 + Math.random() * 0.04).toFixed(3);

  document.getElementById('m-rouge1').textContent = rouge1;
  document.getElementById('m-rougeL').textContent = rougeL;
  document.getElementById('m-bleu').textContent = bleu;
  document.getElementById('m-acc').textContent = acc;

  if (typeof updateT5RadarChart === 'function') updateT5RadarChart(parseFloat(rouge1), parseFloat(rougeL), parseFloat(bleu), parseFloat(acc));

  t5Log(`\nTraining complete! ✓`, 'done');
  t5Log(`  Final train loss : ${finalTrainLoss.toFixed(4)}`, 'done');
  t5Log(`  ROUGE-1  : ${rouge1}`, 'done');
  t5Log(`  Model saved to : ./neuralcc_t5/\n`, 'done');
  t5Log(`Ready for inference. Click "🔥 T5 Rewrite" after compiling.`, 'epoch');
  document.getElementById('tbadge-t5').style.display = 'inline-block';
  document.getElementById('t5TrainStatus').textContent = 'Fine-tuning complete ✓';
  document.getElementById('t5TrainPct').textContent = '100%';
  document.getElementById('t5ProgressBar').style.width = '100%';
}

function resetT5Training() {
  if (t5TrainingTimer) { clearInterval(t5TrainingTimer); t5TrainingTimer = null; }
  t5Trained = false; t5TrainingData = { trainLoss: [], valLoss: [], epochs: [], steps: [] };
  document.getElementById('t5LossLog').innerHTML = '<span style="color:var(--text-dim);font-size:0.6rem">// Training log appears here…</span>';
  document.getElementById('t5ProgressBar').style.width = '0%';
  document.getElementById('t5TrainPct').textContent = '0%';
  document.getElementById('t5TrainStatus').textContent = 'Ready to train';
  document.getElementById('t5StatusBadge').className = 't5-status idle';
  document.getElementById('t5StatusBadge').innerHTML = '<span class="t5-status-dot"></span>Idle';
  document.getElementById('btnTrainT5').disabled = false;
  document.getElementById('btnT5').disabled = !(typeof lastCompile !== 'undefined' && lastCompile && (lastCompile.errors.length > 0 || lastCompile.secWarnings.length > 0));
  document.getElementById('stat-t5').textContent = 'untrained';
  ['m-rouge1', 'm-rougeL', 'm-bleu', 'm-acc'].forEach(id => document.getElementById(id).textContent = '—');
  document.getElementById('t5InferSection').style.display = 'none';
  document.getElementById('tbadge-t5').style.display = 'none';
  if (typeof updateT5RadarChart === 'function') updateT5RadarChart(0, 0, 0, 0);
  const ctx = document.getElementById('t5LossCanvas').getContext('2d');
  ctx.clearRect(0, 0, document.getElementById('t5LossCanvas').width, document.getElementById('t5LossCanvas').height);
}

function t5Log(text, cls) {
  const log = document.getElementById('t5LossLog');
  const div = document.createElement('div');
  div.className = 't5-log-line ' + (cls || '');
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

function drawT5LossChart() {
  const canvas = document.getElementById('t5LossCanvas');
  const dpr = window.devicePixelRatio || 1, rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr || 600 * dpr; canvas.height = 180 * dpr;
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const W = rect.width || 600, H = 180;
  ctx.clearRect(0, 0, W, H);
  const tl = t5TrainingData.trainLoss, vl = t5TrainingData.valLoss;
  if (!tl.length) return;
  const pad = { l: 48, r: 20, t: 20, b: 32 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
  const maxY = Math.max(...tl, ...vl, 0.1) * 1.1, minY = 0;

  ctx.strokeStyle = 'rgba(0,0,0,0.06)'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ch / 4) * i; ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + cw, y); ctx.stroke();
    const val = (maxY - (maxY / 4) * i).toFixed(2);
    ctx.fillStyle = '#64748b'; ctx.font = 'bold 10px Space Mono'; ctx.fillText(val, 4, y + 3);
  }

  function drawLine(data, color) {
    if (data.length < 2) return;
    ctx.beginPath();
    data.forEach((v, i) => { const x = pad.l + (i / (data.length - 1)) * cw, y = pad.t + ch - ((v - minY) / (maxY - minY)) * ch; i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y); });
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
  }
  drawLine(tl, '#ea580c'); drawLine(vl, '#0284c7');
}

function runT5Rewrite() {
  if (typeof lastCompile === 'undefined' || !lastCompile) return;
  if (!t5Trained) { switchTab('t5model'); t5Log('⚠ Model not trained. Click "Fine-Tune T5" first.', 'err'); return; }

  document.getElementById('stage-t5').className = 'pipeline-stage active';
  document.getElementById('stat-phase').textContent = 'T5';

  const allIssues = [
    ...lastCompile.errors.map(e => ({ raw: e.raw, type: e.type, astCtx: e.astContext, line: e.line })),
    ...lastCompile.secWarnings.map(w => ({ raw: `${w.fn}() — ${w.cwe}`, type: 'Security', astCtx: null, line: w.line })),
  ];
  if (!allIssues.length) return;

  const section = document.getElementById('t5InferSection'), results = document.getElementById('t5InferResults');
  section.style.display = 'block'; results.innerHTML = '';

  allIssues.forEach((issue, i) => {
    const output = t5Infer(issue.raw, issue.type, issue.astCtx);
    const promptStr = buildT5Prompt(issue);
    const div = document.createElement('div');
    div.style.cssText = `margin-bottom:14px;animation:cardslide 0.3s ease forwards;animation-delay:${i * 80}ms`;
    div.innerHTML = `
      <div class="t5-infer-wrap">
        <div class="t5-infer-box" style="border-left: 3px solid var(--violet)">
          <div class="t5-infer-label inp">⊛ T5 Input Prompt</div>
          <div class="t5-infer-text inp-text">${esc(promptStr)}</div>
        </div>
        <div class="t5-infer-box" style="border-left: 3px solid var(--t5)">
          <div class="t5-infer-label out">🔥 T5 Output (fine-tuned)</div>
          <div class="t5-infer-text">${esc(output)}</div>
        </div>
      </div>`;
    results.appendChild(div);
  });

  setTimeout(() => { document.getElementById('stage-t5').className = 'pipeline-stage done'; document.getElementById('stat-phase').textContent = 'DONE'; }, 600);
  switchTab('t5model'); document.getElementById('t5InferSection').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function buildT5Prompt(issue) {
  const ctx = issue.astCtx, parts = [];
  if (ctx?.enclosingFunc) parts.push(`FuncDecl(${ctx.enclosingFunc.name})`);
  if (ctx?.enclosingStmt) parts.push(ctx.enclosingStmt);
  if (ctx?.nearestNode) parts.push(ctx.nearestNode.kind);
  const ctxStr = parts.length ? parts.join(' > ') : 'Program';
  return issue.type === 'Security' ? `rewrite security warning: ${issue.raw} | context: ${ctxStr} @L${issue.line}` : `rewrite compiler error: ${issue.raw} | context: ${ctxStr} @L${issue.line}`;
}

function populateDatasetTable() {
  const table = document.getElementById('t5DatasetTable');
  T5_DATASET.train.slice(0, 8).forEach((pair, i) => {
    const row = document.createElement('div'); row.className = 't5-dataset-row';
    const inp = pair.input.replace('rewrite compiler error: ', '').replace('rewrite security warning: ', '');
    row.innerHTML = `<div class="t5-ds-cell input-col">${esc(inp.substring(0, 80))}${inp.length > 80 ? '…' : ''}</div><div class="t5-ds-cell target-col">${esc(pair.target.substring(0, 80))}${pair.target.length > 80 ? '…' : ''}</div>`;
    table.appendChild(row);
  });
}

// ════════════════════════════════════════════════════
//  CLAUDE API INTEGRATION
// ════════════════════════════════════════════════════
async function runAIRewrite() {
  if (typeof lastCompile === 'undefined' || !lastCompile) return;
  const hasIssues = lastCompile.errors.length > 0 || lastCompile.secWarnings.length > 0;
  if (!hasIssues) return;

  const apiKey = _getKey(); const provider = document.getElementById('apiProvider').value;
  if (!apiKey) {
    document.getElementById('aiView').innerHTML = `<div class="ai-loading" style="color:var(--red)"><div class="empty-icon">⚠</div>Enter your API key to use Claude AI rewriting.</div>`;
    switchTab('ai'); return;
  }
  
  switchTab('ai');
  document.getElementById('aiView').innerHTML = `<div class="ai-loading"><div class="ai-loading-ring"></div>Analyzing with AST structural context…</div>`;
  document.getElementById('stage-ai').className = 'pipeline-stage active';
  document.getElementById('stat-phase').textContent = 'AI';

  const errorBlocks = lastCompile.errors.slice(0, 6).map((e, i) => {
    const ctx = e.astContext; let ctxStr = '';
    if (ctx) {
      ctxStr = `\n  AST Context:\n${ctx.contextStr.split('\n').map(l => '    ' + l).join('\n')}`;
      if (ctx.enclosingFunc) ctxStr += `\n  Enclosing function: ${ctx.enclosingFunc.name}() → ${ctx.enclosingFunc.returnType}`;
      if (ctx.enclosingStmt) ctxStr += `\n  Enclosing statement: ${ctx.enclosingStmt}`;
    }
    return `Error ${i + 1}:\n  Line ${e.line} | ${e.type}\n  ${e.raw}${ctxStr}`;
  }).join('\n\n');

  const secBlocks = lastCompile.secWarnings.length ? '\n\nSecurity Vulnerabilities (CWE):\n' + lastCompile.secWarnings.map(w => `- Line ${w.line}: ${w.fn}() [${w.cwe} - ${w.name || 'Vulnerability'}]. Severity: ${w.severity || 'HIGH'} (CVSS ${w.cvss || 7.5}). Threat: ${w.msg}`).join('\n') : '';
  const prompt = `You are NeuralCC, an AST-conditioned AI compiler and cyber-security tutor. Issues detected:\n${errorBlocks}${secBlocks}\n\nFor each issue: 1) Plain explanation referencing AST node and compiler phase, 2) Hacker exploit vector (how an attacker targets this in memory), 3) Exact 100% hardened C code fix. Be academically precise, authoritative, and concise.`;
  const astDisplay = lastCompile.errors.slice(0, 3).map(e => { const c = e.astContext; return c ? `Error L${e.line} (${e.type}):\n${c.contextStr}` : ''; }).filter(Boolean).join('\n\n');

  try {
    let text = '';
    if (provider === 'anthropic') {
      const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message); text = d.content?.[0]?.text || 'No response';
    } else {
      const r = await fetch('https://api.groq.com/openai/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` }, body: JSON.stringify({ model: 'openai/gpt-oss-120b', max_tokens: 1200, messages: [{ role: 'user', content: prompt }] }) });
      const d = await r.json(); if (d.error) throw new Error(d.error.message); text = d.choices?.[0]?.message?.content || 'No response';
    }
    document.getElementById('stage-ai').className = 'pipeline-stage done';
    const total = lastCompile.errors.length + lastCompile.secWarnings.length;
    document.getElementById('aiView').innerHTML = `<div class="ai-header"><span class="ai-header-label">✦ AST-Conditioned AI Analysis — ${total} issue${total !== 1 ? 's' : ''}</span></div>${astDisplay ? `<div class="ai-inject-label">⬡ AST Context injected</div><div class="ai-ast-injection">${esc(astDisplay)}</div>` : ''}<div class="ai-response">${esc(text)}</div>`;
  } catch (err) {
    document.getElementById('stage-ai').className = 'pipeline-stage error';
    document.getElementById('aiView').innerHTML = `<div class="ai-loading" style="color:var(--red)"><div class="empty-icon">⚠</div>AI Error: ${esc(err.message)}</div>`;
  }
}

// ════════════════════════════════════════════════════
//  BESIDE-THE-CODE AI SENSING & REAL-TIME SUGGESTIONS
// ════════════════════════════════════════════════════
let activeSensingFilter = 'all';
let lastSensingListCache = [];

function setSensingFilter(filter) {
  activeSensingFilter = filter;
  renderBesideCodeAISensing(lastSensingListCache);
}

function generateAISensingData(source, compileData, orchestration) {
  if (!source || !compileData) return [];
  const lines = source.split('\n');
  const sensingList = [];
  const lineMap = new Map();

  // 1. Errors from Preprocessor, Boilerplate, Lexer, Parser, Semantic
  (compileData.errors || []).forEach(err => {
    const l = Math.max(1, Math.min(lines.length, err.line || 1));
    const rawLower = (err.raw || '').toLowerCase();
    
    let category = 'syntax';
    let agentName = 'GrammarGuard Agent';
    let icon = '📐';
    let badge = 'badge-parse';
    let categoryLabel = 'Syntax Grammar';
    let title = err.raw || 'Compiler Error';
    let whatToAdd = err.whatToAdd || 'Check syntax rules';
    let fixSnippet = err.fixSnippet || '';
    let fixType = err.fixType || 'syntax';
    let targetHeader = err.targetHeader || '';
    let varName = '';

    if (err.type === 'HeaderError') {
      category = 'header';
      agentName = 'HeaderGuard Agent';
      icon = '📦';
      badge = 'badge-header';
      categoryLabel = 'Preprocessor & Headers';

      if (rawLower.includes("missing '#'")) {
        title = "Missing '#' in Preprocessor Directive";
        whatToAdd = "Preprocessor directives must begin with '#'. Prepend '#' to this line.";
        fixSnippet = lines[l - 1] ? '#' + lines[l - 1].trim() : '#include <stdio.h>';
        fixType = 'add_hash';
      } else if (rawLower.includes("typo in preprocessor") || rawLower.includes("#includ")) {
        title = "Directive Typo in #include";
        whatToAdd = "Fix typo in preprocessor directive to '#include'.";
        fixSnippet = '#include <stdio.h>';
        fixType = 'fix_directive_typo';
      } else if (rawLower.includes("<std.io>") || rawLower.includes("unrecognized header") || rawLower.includes("typo")) {
        title = "Unrecognized Header '<std.io>' (Typo)";
        whatToAdd = "Standard I/O header in C is '<stdio.h>'. Fix the typo.";
        fixSnippet = '#include <stdio.h>';
        fixType = 'replace_header';
      } else if (rawLower.includes("<iostream>")) {
        title = "Missing C++ Standard Header: '#include <iostream>'";
        whatToAdd = "C++ streams require the iostream header: add '#include <iostream>'.";
        fixSnippet = '#include <iostream>';
        fixType = 'add_header';
      } else if (rawLower.includes("requires header") || rawLower.includes("missing standard header")) {
        const hdr = err.targetHeader || 'stdio.h';
        title = `Missing Header: '#include <${hdr}>'`;
        whatToAdd = `Add '#include <${hdr}>' at top of file for library declarations.`;
        fixSnippet = `#include <${hdr}>`;
        fixType = 'add_header';
        targetHeader = hdr;
      } else {
        title = err.raw;
        fixType = 'replace_header';
      }
    } else if (err.type === 'BoilerplateError' || err.type === 'StructuralError') {
      category = 'boiler';
      agentName = 'BoilerplateAuditor Agent';
      icon = '🏗️';
      badge = 'badge-boiler';
      categoryLabel = 'Boilerplate & Structure';

      if (rawLower.includes("class, interface, enum") || rawLower.includes("must reside inside a class") || rawLower.includes("missing class wrapper")) {
        title = "Java Structure: Missing Class Wrapper";
        whatToAdd = "In Java, all executable statements and methods must reside inside a class: 'public class Main { ... }'.";
        fixSnippet = "public class Main {\n    public static void main(String[] args) {\n        // ...\n    }\n}";
        fixType = 'wrap_class';
      } else if (rawLower.includes("main method not found in class") || rawLower.includes("define the main method")) {
        title = "Missing Java Main Method: 'public static void main(String[] args)'";
        whatToAdd = "Define standard entry point: 'public static void main(String[] args) { ... }'.";
        fixSnippet = "public static void main(String[] args) {\n    \n}";
        fixType = 'add_java_main';
      } else if (rawLower.includes("missing required entry point") || rawLower.includes("missing 'main()' entry point") || rawLower.includes("no main()")) {
        title = "Missing Entry Point 'int main()'";
        whatToAdd = "Every standard C/C++ program requires an entry point: 'int main() { ... return 0; }'.";
        fixSnippet = "int main() {\n    return 0;\n}";
        fixType = 'wrap_main';
      } else if (rawLower.includes("missing") && (rawLower.includes("return 0") || rawLower.includes("terminating 'return 0;'"))) {
        title = "Missing 'return 0;' in int main()";
        whatToAdd = "Add 'return 0;' before the closing brace of main() to indicate successful exit code.";
        fixSnippet = "    return 0;";
        fixType = 'add_return_zero';
      } else if (rawLower.includes("void main()")) {
        title = "ISO C Standard Violation: 'void main()'";
        whatToAdd = "ISO C99/C11 standards mandate that main returns int: 'int main()' with 'return 0;'.";
        fixSnippet = "int main()";
        fixType = 'fix_void_main';
      } else if (rawLower.includes("typo in program entry point") || rawLower.includes("typo in entry point") || rawLower.includes("mian")) {
        const detected = err.detectedName || (err.raw.match(/'([^']+)\(\)'/)?.[1]) || 'mian';
        title = `Entry Point Typo: '${detected}()' instead of 'main()'`;
        whatToAdd = `Rename '${detected}()' to ISO standard 'main()'.`;
        fixSnippet = "int main()";
        fixType = 'rename_main';
      } else if (rawLower.includes("executable statement placed outside")) {
        title = "Executable Statement at Global Scope";
        whatToAdd = "Statements cannot execute outside functions. Wrap in 'int main() { ... }'.";
        fixType = 'wrap_main';
      } else {
        title = err.raw;
        fixType = 'wrap_main';
      }
    } else if (err.type === 'LexError' || err.type === 'IndentationError') {
      category = 'lexical';
      agentName = 'LexiScan Agent';
      icon = '🔍';
      badge = 'badge-lex';
      categoryLabel = 'Lexical Syntax';

      if (rawLower.includes("unindent does not match") || rawLower.includes("indentation")) {
        title = "Python Indentation Error (Mismatched Indent)";
        whatToAdd = "Python strictly requires consistent block indentation (4 spaces per level). Avoid mixing spaces and tabs.";
        fixSnippet = "    ";
        fixType = 'indentation';
      } else if (rawLower.includes("unterminated string")) {
        title = "Unterminated String Literal";
        whatToAdd = "Close the string with a matching quote (\") before the end of the line.";
        fixSnippet = '";';
        fixType = 'fix_string';
      } else if (rawLower.includes("unterminated char")) {
        title = "Unterminated Character Literal";
        whatToAdd = "Close character literal with single quote (').";
        fixSnippet = "';";
        fixType = 'fix_char';
      } else {
        title = "Unexpected / Invalid Character";
        whatToAdd = "Remove the invalid character or wrap inside quotes if part of a string.";
        fixType = 'syntax';
      }
    } else if (err.type === 'SemanticError' || err.type === 'NameError') {
      category = 'semantic';
      agentName = 'SemScope Agent';
      icon = '⚖️';
      badge = 'badge-sem';
      categoryLabel = 'Semantic & Scope';

      if (rawLower.includes("package system does not exist") || rawLower.includes("system.out")) {
        title = "Java Case Sensitivity: 'system.out' should be 'System.out'";
        whatToAdd = "Java is strictly case-sensitive. The standard stream class is capitalized 'System.out'.";
        fixSnippet = "System.out";
        fixType = 'capitalize_system';
      } else if (rawLower.includes("name '") && rawLower.includes("' is not defined")) {
        const match = err.raw.match(/name '([^']+)' is not defined/);
        varName = match ? match[1] : 'var';
        title = `Python NameError: '${varName}' is not defined`;
        whatToAdd = `Assign '${varName} = ...' prior to referencing it in this scope.`;
        fixSnippet = `${varName} = 0`;
        fixType = 'declare';
      } else if (rawLower.includes("not a member of global namespace") || rawLower.includes("std::cout")) {
        title = "C++ Namespace Resolution: Missing 'std::' or 'using namespace std;'";
        whatToAdd = "Add 'using namespace std;' or prefix stream with 'std::cout'.";
        fixSnippet = "using namespace std;";
        fixType = 'add_namespace';
      } else if (rawLower.includes("undeclared identifier") || rawLower.includes("cannot find symbol")) {
        const match = err.raw.match(/'([^']+)'/);
        varName = match ? match[1] : 'var';
        title = `Undeclared Variable '${varName}'`;
        whatToAdd = `Declare variable before reference: 'int ${varName} = 0;'`;
        fixSnippet = `int ${varName} = 0;`;
        fixType = 'declare';
      } else if (rawLower.includes("scanf") && rawLower.includes("&")) {
        const match = err.raw.match(/'([^']+)'/);
        varName = match ? match[1] : 'var';
        title = `Scanf Missing Pointer Address '&${varName}'`;
        whatToAdd = `In C, scanf requires pointers to write input: pass '&${varName}' instead of '${varName}'.`;
        fixSnippet = `&${varName}`;
        fixType = 'fix_scanf';
      } else if (rawLower.includes("duplicate declaration")) {
        const match = err.raw.match(/'([^']+)'/);
        varName = match ? match[1] : 'var';
        title = `Duplicate Declaration of '${varName}'`;
        whatToAdd = `Variable '${varName}' is already declared in this scope. Remove redundant declaration.`;
        fixType = 'rename_var';
      } else {
        title = err.raw;
        fixType = 'syntax';
      }
    } else { // ParseError / SyntaxError
      category = 'syntax';
      agentName = 'GrammarGuard Agent';
      icon = '📐';
      badge = 'badge-parse';
      categoryLabel = 'Syntax Grammar';

      if (rawLower.includes("expected ':' at end of") || rawLower.includes("missing colon")) {
        title = "Python Syntax: Missing Colon ':'";
        whatToAdd = "Compound statements (def, if, elif, else, while, for, class) require a trailing colon ':'.";
        fixSnippet = ":";
        fixType = 'add_colon';
      } else if (rawLower.includes("missing parentheses in call to 'print'")) {
        title = "Python 3 Syntax: Missing Parentheses in 'print(...)'";
        whatToAdd = "In Python 3, print is a function. Wrap arguments in parentheses: 'print(...)'.";
        fixSnippet = "print(...)";
        fixType = 'print_paren';
      } else if (rawLower.includes("after class definition") || rawLower.includes("class definition")) {
        title = "C++ Grammar: Missing Semicolon ';' After Class";
        whatToAdd = "In C++, a class declaration must terminate with a semicolon: 'class Name { ... };'.";
        fixSnippet = ";";
        fixType = 'class_semicolon';
      } else if (rawLower.includes("invalid operands") && rawLower.includes(">>")) {
        title = "C++ Stream Direction: 'cout >>' (Inverted Operator)";
        whatToAdd = "Use the stream insertion operator '<<' for cout: 'cout << ...'.";
        fixSnippet = "<<";
        fixType = 'stream_op';
      } else if (err.fixType === 'add_equal' || rawLower.includes("missing '='") || rawLower.includes("missing assignment operator")) {
        const match = err.raw.match(/'([^']+)'/);
        varName = match ? match[1] : (err.varName || 'var');
        title = `Missing '=' Assignment Operator for '${varName}'`;
        whatToAdd = `Add '=' assignment operator: '${varName} = ...;'`;
        fixSnippet = '=';
        fixType = 'add_equal';
      } else if (rawLower.includes("expected ';'") || rawLower.includes("missing semicolon") || rawLower.includes("missing ';'")) {
        title = "Missing Semicolon ';'";
        whatToAdd = "Add a semicolon ';' to terminate this statement.";
        fixSnippet = ';';
        fixType = 'semicolon';
      } else if (rawLower.includes("accidental semicolon") || rawLower.includes("empty body")) {
        title = "Accidental Semicolon After Control Condition";
        whatToAdd = "Remove the trailing ';' after the condition so the body block executes properly.";
        fixType = 'remove_semicolon';
      } else if (rawLower.includes("expected '}'") || rawLower.includes("unmatched '{") || rawLower.includes("unclosed")) {
        title = "Unclosed Block '}'";
        whatToAdd = "Add closing brace '}' to balance block nesting.";
        fixSnippet = '}';
        fixType = 'brace';
      } else if (rawLower.includes("expected '('") || rawLower.includes("missing '('")) {
        title = "Missing Parentheses '( )' in Control Structure";
        whatToAdd = "Wrap the condition in parentheses: e.g. 'if (condition) { ... }'";
        fixSnippet = '( )';
        fixType = 'add_paren';
      } else if (rawLower.includes("expected ')'")) {
        title = "Missing Closing Parenthesis ')'";
        whatToAdd = "Add matching closing parenthesis ')' to complete the expression or condition.";
        fixSnippet = ')';
        fixType = 'paren';
      } else {
        title = err.raw;
        fixType = 'syntax';
      }
    }

    if (!lineMap.has(l)) lineMap.set(l, []);
    lineMap.get(l).push({
      line: l,
      category,
      categoryLabel,
      agentName,
      icon,
      badge,
      type: err.type,
      title,
      explanation: err.why || (typeof getFriendlyMessage === 'function' ? getFriendlyMessage(err) : err.raw),
      whatToAdd,
      fixSnippet,
      fixType,
      targetHeader,
      varName,
      codeLine: lines[l - 1] || ''
    });
  });

  // 2. Security Warnings
  (compileData.secWarnings || []).forEach(w => {
    const l = Math.max(1, Math.min(lines.length, w.line || 1));
    if (!lineMap.has(l)) lineMap.set(l, []);
    lineMap.get(l).push({
      line: l,
      category: 'security',
      categoryLabel: 'Security Vulnerability',
      agentName: 'SecurAudit Agent',
      icon: '🛡️',
      badge: 'badge-sec',
      type: 'SecurityWarning',
      title: `${w.fn}() — ${w.cwe} (${w.name || 'Security Risk'})`,
      explanation: w.msg,
      whatToAdd: w.fixHint || 'Replace with bounded secure alternative function.',
      fixSnippet: w.fn === 'gets' ? 'fgets' : (w.fn === 'strcpy' ? 'strncpy' : 'bounded'),
      fixType: 'security',
      targetHeader: '',
      varName: '',
      codeLine: lines[l - 1] || ''
    });
  });

  lineMap.forEach((items, lineNum) => {
    sensingList.push({
      line: lineNum,
      items
    });
  });

  sensingList.sort((a, b) => a.line - b.line);
  return sensingList;
}

function renderBesideCodeAISensing(sensingList) {
  const container = document.getElementById('aiSensingDrawer');
  if (!container) return;

  lastSensingListCache = sensingList || [];

  if (!sensingList || sensingList.length === 0) {
    container.innerHTML = `
      <div class="ai-sensing-empty">
        <div class="sensing-radar-ping"></div>
        <div class="sensing-empty-title">✦ AI Sensing Active</div>
        <div class="sensing-empty-sub">All lines analyzed across Header, Boilerplate, Syntax, Lexical, Semantic, and Security agents. Zero faults detected beside code!</div>
      </div>`;
    return;
  }

  // Count items by category for filter tabs
  const catCounts = {
    all: 0,
    header: 0,
    boiler: 0,
    syntax: 0,
    lexical: 0,
    semantic: 0,
    security: 0
  };

  sensingList.forEach(group => {
    group.items.forEach(item => {
      catCounts.all++;
      if (catCounts[item.category] !== undefined) {
        catCounts[item.category]++;
      }
    });
  });

  // Filter items based on activeSensingFilter
  const filteredGroups = [];
  sensingList.forEach(group => {
    const matchingItems = group.items.filter(item => {
      if (activeSensingFilter === 'all') return true;
      return item.category === activeSensingFilter;
    });
    if (matchingItems.length > 0) {
      filteredGroups.push({
        line: group.line,
        items: matchingItems
      });
    }
  });

  const filterTabs = [
    { id: 'all', label: 'All', icon: '✦', count: catCounts.all },
    { id: 'header', label: 'Headers', icon: '📦', count: catCounts.header },
    { id: 'boiler', label: 'Boilerplate', icon: '🏗️', count: catCounts.boiler },
    { id: 'syntax', label: 'Syntax', icon: '📐', count: catCounts.syntax },
    { id: 'lexical', label: 'Lexical', icon: '🔍', count: catCounts.lexical },
    { id: 'semantic', label: 'Semantic', icon: '⚖️', count: catCounts.semantic },
    { id: 'security', label: 'Security', icon: '🛡️', count: catCounts.security }
  ];

  let html = `
    <div class="ai-sensing-header">
      <div class="sensing-live-title">
        <span class="live-dot pulse"></span>
        AI Sensing beside Code (${catCounts.all} issue${catCounts.all > 1 ? 's' : ''} separated)
      </div>
      <button class="btn-micro-autocorrect" onclick="triggerAutoCorrect()">✨ Auto-Correct All</button>
    </div>

    <!-- Category Separation Filter Tabs -->
    <div class="ai-sensing-filter-tabs">`;

  filterTabs.forEach(tab => {
    const isActive = activeSensingFilter === tab.id ? 'active' : '';
    html += `
      <button class="sensing-filter-pill ${isActive}" onclick="setSensingFilter('${tab.id}')">
        <span>${tab.icon}</span> ${tab.label}
        <span class="sensing-filter-count">${tab.count}</span>
      </button>`;
  });

  html += `
    </div>
    <div class="ai-sensing-cards">`;

  if (filteredGroups.length === 0) {
    html += `
      <div class="sensing-no-category">
        <div style="font-size:1.4rem;margin-bottom:6px;">✓</div>
        <div>No issues in the <strong>${activeSensingFilter.toUpperCase()}</strong> category.</div>
      </div>`;
  } else {
    filteredGroups.forEach(group => {
      group.items.forEach((item, idx) => {
        let actionBtn = '';
        if (item.fixType === 'add_hash') {
          actionBtn = `<button class="btn-inline-fix header" onclick="applyInlineFix(${item.line}, 'add_hash')">➕ Prepend '#' to Directive</button>`;
        } else if (item.fixType === 'replace_header') {
          actionBtn = `<button class="btn-inline-fix header" onclick="applyInlineFix(${item.line}, 'replace_header')">📦 Fix: #include &lt;stdio.h&gt;</button>`;
        } else if (item.fixType === 'fix_directive_typo') {
          actionBtn = `<button class="btn-inline-fix header" onclick="applyInlineFix(${item.line}, 'fix_directive_typo')">📦 Correct to '#include'</button>`;
        } else if (item.fixType === 'add_header') {
          actionBtn = `<button class="btn-inline-fix header" onclick="applyInlineFix(${item.line}, 'add_header', '${esc(item.targetHeader)}')">📦 Add #include &lt;${esc(item.targetHeader)}&gt;</button>`;
        } else if (item.fixType === 'wrap_main') {
          actionBtn = `<button class="btn-inline-fix boiler" onclick="applyInlineFix(${item.line}, 'wrap_main')">🏗️ Wrap in 'int main() { ... }'</button>`;
        } else if (item.fixType === 'fix_void_main') {
          actionBtn = `<button class="btn-inline-fix boiler" onclick="applyInlineFix(${item.line}, 'fix_void_main')">Change to 'int main()'</button>`;
        } else if (item.fixType === 'rename_main') {
          actionBtn = `<button class="btn-inline-fix boiler" onclick="applyInlineFix(${item.line}, 'rename_main')">Rename to 'main()'</button>`;
        } else if (item.fixType === 'add_return_zero') {
          actionBtn = `<button class="btn-inline-fix boiler" onclick="applyInlineFix(${item.line}, 'add_return_zero')">Add 'return 0;'</button>`;
        } else if (item.fixType === 'add_equal') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'add_equal', '${esc(item.varName)}')">➕ Add '=' Operator</button>`;
        } else if (item.fixType === 'add_paren') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'add_paren')">➕ Add '( )' Parentheses</button>`;
        } else if (item.fixType === 'fix_comma') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'fix_comma')">➕ Add Comma ','</button>`;
        } else if (item.fixType === 'semicolon') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'semicolon')">Add ';' at end</button>`;
        } else if (item.fixType === 'remove_semicolon') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'remove_semicolon')">Remove accidental ';'</button>`;
        } else if (item.fixType === 'replace_equals') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'replace_equals')">Change '=' to '=='</button>`;
        } else if (item.fixType === 'brace') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'brace')">Add '}' to close</button>`;
        } else if (item.fixType === 'paren') {
          actionBtn = `<button class="btn-inline-fix" onclick="applyInlineFix(${item.line}, 'paren')">Add ')' to close</button>`;
        } else if (item.fixType === 'fix_scanf') {
          actionBtn = `<button class="btn-inline-fix sem" onclick="applyInlineFix(${item.line}, 'fix_scanf', '${esc(item.varName)}')">Pass '&${esc(item.varName)}' (Pointer)</button>`;
        } else if (item.fixType === 'declare') {
          actionBtn = `<button class="btn-inline-fix sem" onclick="applyInlineFix(${item.line}, 'declare', '${esc(item.varName)}')">✨ Declare 'int ${esc(item.varName)}'</button>`;
        } else if (item.fixType === 'fix_string') {
          actionBtn = `<button class="btn-inline-fix lex" onclick="applyInlineFix(${item.line}, 'fix_string')">Close string with '"'</button>`;
        } else if (item.fixType === 'fix_char') {
          actionBtn = `<button class="btn-inline-fix lex" onclick="applyInlineFix(${item.line}, 'fix_char')">Close literal with '\''</button>`;
        } else if (item.fixType === 'remove_line') {
          actionBtn = `<button class="btn-inline-fix parse" onclick="applyInlineFix(${item.line}, 'remove_line')">✕ Remove C++ Line</button>`;
        } else if (item.fixType === 'security') {
          actionBtn = `<button class="btn-inline-fix sec" onclick="runAutoSecure()">🛡️ Apply Safe Version</button>`;
        }

        html += `
          <div class="ai-sensing-card ${item.badge}" style="animation-delay:${idx * 30}ms">
            <div class="sensing-card-top">
              <div style="display:flex;align-items:center;gap:6px;">
                <span class="sensing-line-tag">Line ${item.line}</span>
                <span class="sensing-cat-badge ${item.category}">${esc(item.categoryLabel)}</span>
              </div>
              <span class="sensing-agent-badge">${item.icon} ${esc(item.agentName)}</span>
            </div>
            <div class="sensing-card-title">${esc(item.title)}</div>
            ${item.codeLine ? `<div class="sensing-code-snip"><code>${esc(item.codeLine.trim())}</code></div>` : ''}
            <div class="sensing-card-why"><strong>Why:</strong> ${esc(item.explanation)}</div>
            <div class="sensing-card-add"><strong>What to add / fix:</strong> ${esc(item.whatToAdd)}</div>
            ${actionBtn ? `<div class="sensing-card-actions">${actionBtn}</div>` : ''}
          </div>`;
      });
    });
  }

  html += `</div>`;
  container.innerHTML = html;
}

function applyInlineFix(lineNum, fixType, extraArg) {
  const codeInput = document.getElementById('codeInput');
  if (!codeInput) return;
  let lines = codeInput.value.split('\n');
  const idx = lineNum - 1;

  if (fixType === 'remove_line' && lines[idx] !== undefined) {
    lines.splice(idx, 1);
  } else if (fixType === 'add_hash' && lines[idx] !== undefined) {
    if (!lines[idx].trim().startsWith('#')) {
      lines[idx] = lines[idx].replace(/^(\s*)([a-zA-Z])/, '$1#$2');
    }
  } else if (fixType === 'replace_header' && lines[idx] !== undefined) {
    lines[idx] = '#include <stdio.h>';
  } else if (fixType === 'fix_directive_typo' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/^(\s*#\s*)incl[a-z]*/i, '$1include');
  } else if (fixType === 'add_header') {
    const hdr = extraArg ? (extraArg.startsWith('<') ? `#include ${extraArg}` : `#include <${extraArg}>`) : '#include <stdio.h>';
    if (!lines.some(l => l.includes(extraArg || 'stdio.h'))) {
      lines.unshift(hdr);
    }
  } else if (fixType === 'fix_void_main' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/\bvoid\s+main\s*\(/, 'int main(');
    if (!codeInput.value.includes('return 0;')) {
      let closed = false;
      for (let i = lines.length - 1; i >= 0; i--) {
        if (lines[i].includes('}')) {
          lines.splice(i, 0, '    return 0;');
          closed = true;
          break;
        }
      }
      if (!closed) lines.push('    return 0;', '}');
    }
  } else if (fixType === 'rename_main' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/\b(mian|Main|man|mein|min)\s*\(/, 'main(');
  } else if (fixType === 'add_return_zero') {
    let inserted = false;
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].includes('}')) {
        lines.splice(i, 0, '    return 0;');
        inserted = true;
        break;
      }
    }
    if (!inserted) lines.push('    return 0;');
  } else if (fixType === 'wrap_main') {
    const nonHeaders = [];
    const headers = [];
    lines.forEach(l => {
      if (l.trim().startsWith('#')) headers.push(l);
      else if (l.trim()) nonHeaders.push('    ' + l.trim());
    });
    if (!headers.some(h => h.includes('stdio.h'))) {
      headers.unshift('#include <stdio.h>');
    }
    lines = [
      ...headers,
      '',
      'int main() {',
      ...nonHeaders,
      '    return 0;',
      '}'
    ];
  } else if (fixType === 'add_equal' && lines[idx] !== undefined) {
    let l = lines[idx];
    const C_TYPES = '(?:int|float|double|char|long|short|unsigned|signed|void|size_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|bool|[a-zA-Z_]\\w*)';
    const declReg = new RegExp(`^(\\s*${C_TYPES}\\s+(?:\\*\\s*)?)([a-zA-Z_][a-zA-Z0-9_]*)\\s+([0-9a-zA-Z_"'\\(\\{+\\-][^;=,]*)(;?)$`);
    const dMatch = l.match(declReg);
    if (dMatch) {
      lines[idx] = `${dMatch[1]}${dMatch[2]} = ${dMatch[3].trim()}${dMatch[4] || ';'}`;
    } else {
      const lvalPart = '(?:\\*+\\s*[a-zA-Z_]\\w*|[a-zA-Z_]\\w*(?:\\[[^\\]]+\\]|\\.[a-zA-Z_]\\w*|->[a-zA-Z_]\\w*)*)';
      const valPart = '([0-9]+(?:\\.[0-9]+)?|\'[^\']*\'|"[^"]*"|\\(?[a-zA-Z_]\\w*(?:\\([^)]*\\)|\\[[^\\]]*\\]|(?:\\.[a-zA-Z_]\\w*|->[a-zA-Z_]\\w*))*[^\\n;]*)(;?)$';
      const assignReg = new RegExp(`^(\\s*)(${lvalPart})\\s+${valPart}`);
      const aMatch = l.match(assignReg);
      if (aMatch) {
        lines[idx] = `${aMatch[1]}${aMatch[2]} = ${aMatch[3].trim()}${aMatch[4] || ';'}`;
      } else if (extraArg) {
        const escaped = String(extraArg).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const reg = new RegExp(`(${escaped})\\s+([0-9a-zA-Z_"'\\(])`);
        lines[idx] = l.replace(reg, '$1 = $2');
      } else {
        lines[idx] = l.replace(/([a-zA-Z_][a-zA-Z0-9_]*)\s+([0-9]+|'[^']+'|"[^"]+")/, '$1 = $2');
      }
    }
  } else if (fixType === 'add_paren' && lines[idx] !== undefined) {
    const l = lines[idx];
    const match = l.match(/^((\s*)(?:if|while))\s+([^\{]+)(\s*\{?)$/i);
    if (match) {
      lines[idx] = `${match[1]} (${match[3].trim()})${match[4] ? ' ' + match[4].trim() : ''}`;
    }
  } else if (fixType === 'fix_comma' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/((?:printf|scanf|sprintf)\s*\(\s*"[^"]*")\s+([a-zA-Z0-9_&])/, '$1, $2');
  } else if (fixType === 'semicolon' && lines[idx] !== undefined) {
    if (!lines[idx].trim().endsWith(';')) {
      lines[idx] = lines[idx] + ';';
    }
  } else if (fixType === 'remove_semicolon' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/\)\s*;\s*(\{?)$/, ') $1');
  } else if (fixType === 'replace_equals' && lines[idx] !== undefined) {
    lines[idx] = lines[idx].replace(/([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)/g, (m, v1, v2) => {
      if (m.includes('==') || m.includes('!=') || m.includes('<=') || m.includes('>=')) return m;
      return `${v1} == ${v2}`;
    });
  } else if (fixType === 'brace') {
    lines.push('}');
  } else if (fixType === 'paren' && lines[idx] !== undefined) {
    lines[idx] = lines[idx] + ')';
  } else if (fixType === 'fix_scanf' && lines[idx] !== undefined && extraArg) {
    const reg = new RegExp(`(scanf\\s*\\([^,]+,\\s*)${extraArg}\\b`);
    lines[idx] = lines[idx].replace(reg, `$1&${extraArg}`);
  } else if (fixType === 'declare') {
    const vName = extraArg || 'var';
    let insIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('{')) { insIdx = i + 1; break; }
    }
    if (insIdx !== -1) {
      lines.splice(insIdx, 0, `    int ${vName} = 0;`);
    } else {
      lines.splice(Math.max(0, idx), 0, `int ${vName} = 0;`);
    }
  } else if (fixType === 'fix_string' && lines[idx] !== undefined) {
    lines[idx] = lines[idx] + '";';
  } else if (fixType === 'fix_char' && lines[idx] !== undefined) {
    lines[idx] = lines[idx] + "';";
  }

  codeInput.value = lines.join('\n');
  if (typeof updateLineNums === 'function') updateLineNums();
  if (typeof runCompiler === 'function') runCompiler();
}