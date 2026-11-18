const ep = require('./enterprise_presets.js');
const c = require('./compiler.js');

console.log('=== VERIFYING ENTERPRISE PRESETS ===');
let allPassed = true;

for (const [key, code] of Object.entries(ep.c)) {
  const lineCount = code.split('\n').length;
  const { tokens } = c.lex(code);
  const p = c.parse(tokens, code);
  const b = c.validateBoilerplateAndStructure(code, tokens, p.ast);
  const sem = c.analyze(p.ast, tokens, code);
  const sec = c.scanSecurity(tokens, p.ast, code);
  const totalDiagnostics = p.errors.length + b.length + sem.length + sec.length;

  console.log(`[${key.padEnd(20)}] Lines: ${String(lineCount).padStart(4)} | ParseErr: ${p.errors.length} | BoilerErr: ${b.length} | SemErr: ${sem.length} | SecWarnings: ${sec.length}`);

  if (key === 'valid' || key === 'massive_enterprise') {
    if (totalDiagnostics !== 0) {
      console.error(`ERROR: ${key} should have 0 diagnostics but got ${totalDiagnostics}`);
      allPassed = false;
    }
  } else {
    if (totalDiagnostics === 0) {
      console.error(`ERROR: ${key} should have detected faults but got 0 diagnostics!`);
      allPassed = false;
    }
  }
}

if (allPassed) {
  console.log('>>> ALL ENTERPRISE PRESETS VERIFIED WITH 100% SUCCESS <<<');
} else {
  console.error('FAILED SOME CHECKS');
  process.exit(1);
}

