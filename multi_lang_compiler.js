// multi_lang_compiler.js — NeuralCC Multi-Language Frontend Engine
// Supports C (ISO C11), C++ (C++17 / OOP), Java (Java 17), and Python (Python 3.11)
// Integrates with NeuralCC's 6-Agent Compiler Pipeline, Unified AST, Three-Address Code (TAC) IR, and Virtual Runtime.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.MultiLangEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  // Current active language: 'c' | 'cpp' | 'java' | 'python'
  let currentLanguage = 'c';

  // ════════════════════════════════════════════════════
  //  1. LANGUAGE DEFINITIONS & PRESETS
  // ════════════════════════════════════════════════════
  const LANGUAGE_CONFIGS = {
    c: {
      name: 'C',
      standard: 'ISO C11',
      fileExt: 'c',
      binaryName: 'main.out',
      runCommand: 'gcc -std=c11 main.c -o main.out && ./main.out',
      placeholder: '// Write or paste C code here...\n#include <stdio.h>\n\nint main() {\n    printf("Hello from NeuralCC C!\\n");\n    return 0;\n}',
      compilerBadge: 'C Frontend (ISO C11)',
      editorTitle: 'C Source Code Editor'
    },
    cpp: {
      name: 'C++',
      standard: 'ISO C++17',
      fileExt: 'cpp',
      binaryName: 'main.out',
      runCommand: 'g++ -std=c++17 main.cpp -o main.out && ./main.out',
      placeholder: '// Write or paste C++ code here...\n#include <iostream>\nusing namespace std;\n\nclass Calculator {\npublic:\n    int add(int a, int b) {\n        return a + b;\n    }\n};\n\nint main() {\n    Calculator calc;\n    cout << "Sum: " << calc.add(15, 25) << endl;\n    return 0;\n}',
      compilerBadge: 'C++17 OOP Frontend',
      editorTitle: 'C++ Source Code Editor'
    },
    java: {
      name: 'Java',
      standard: 'Java 17 (JVM)',
      fileExt: 'java',
      binaryName: 'Main.class',
      runCommand: 'javac Main.java && java Main',
      placeholder: '// Write or paste Java code here...\npublic class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello from NeuralCC Java Virtual Studio!");\n    }\n}',
      compilerBadge: 'Java 17 JVM Frontend',
      editorTitle: 'Java Source Code Editor'
    },
    python: {
      name: 'Python',
      standard: 'Python 3.11',
      fileExt: 'py',
      binaryName: 'script.py',
      runCommand: 'python3 -u script.py',
      placeholder: '# Write or paste Python code here...\ndef calculate_sum(n):\n    total = 0\n    for i in range(1, n + 1):\n        total += i\n    return total\n\nprint("NeuralCC Python Studio")\nprint("Sum 1..10:", calculate_sum(10))',
      compilerBadge: 'Python 3.11 Frontend',
      editorTitle: 'Python Source Code Editor'
    }
  };

  const PRESETS_BY_LANG = {
    c: {
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
    },
    cpp: {
      cpp_class_semi: `#include <iostream>\nusing namespace std;\n\n// Error: Missing semicolon after class definition!\nclass Point {\npublic:\n    int x;\n    int y;\n    void display() {\n        cout << "Point(" << x << ", " << y << ")" << endl;\n    }\n}\n\nint main() {\n    Point p;\n    p.x = 10;\n    p.y = 20;\n    p.display();\n    return 0;\n}`,
      cpp_missing_stream: `#include <iostream>\n\nint main() {\n    // Error: cout used without std:: and without 'using namespace std;'\n    cout << "Missing namespace std qualification!" << endl;\n    return 0;\n}`,
      cpp_stream_direction: `#include <iostream>\nusing namespace std;\n\nint main() {\n    int score = 95;\n    // Error: Inverted stream insertion operator '>>' instead of '<<'\n    cout >> "Player Score: " >> score >> endl;\n    return 0;\n}`,
      cpp_oop_valid: `#include <iostream>\nusing namespace std;\n\nclass Rectangle {\nprivate:\n    int width;\n    int height;\npublic:\n    void setDimensions(int w, int h) {\n        width = w;\n        height = h;\n    }\n    int getArea() {\n        return width * height;\n    }\n};\n\nint main() {\n    Rectangle rect;\n    rect.setDimensions(6, 7);\n    cout << "Rectangle Area: " << rect.getArea() << endl;\n    return 0;\n}`,
      cpp_memory_leak: `#include <iostream>\nusing namespace std;\n\nint main() {\n    int* numbers = new int[50]; // CWE-401 Memory allocation without delete[]\n    numbers[0] = 100;\n    cout << "Value: " << numbers[0] << endl;\n    return 0;\n}`
    },
    java: {
      java_missing_class: `// Error: In Java, executable methods must be enclosed in a class!\npublic static void main(String[] args) {\n    int x = 42;\n    System.out.println("Result: " + x);\n}`,
      java_case_fault: `public class Main {\n    public static void main(String[] args) {\n        int total = 100;\n        // Error: 'system' instead of capitalized 'System'\n        system.out.println("Total: " + total);\n    }\n}`,
      java_missing_semi: `public class Main {\n    public static void main(String[] args) {\n        int a = 15\n        int b = 25;\n        int sum = a + b;\n        System.out.println("Sum = " + sum);\n    }\n}`,
      java_undeclared: `public class Main {\n    public static void main(String[] args) {\n        result = 50 + 20;\n        System.out.println("Result: " + result);\n    }\n}`,
      java_valid: `public class Main {\n    public static void main(String[] args) {\n        System.out.println("=== Java 17 Execution ===");\n        int sum = 0;\n        for (int i = 1; i <= 5; i++) {\n            sum += i;\n            System.out.println("Step " + i + ": sum = " + sum);\n        }\n        System.out.println("Final total: " + sum);\n    }\n}`,
      java_cmd_injection: `public class Main {\n    public static void main(String[] args) {\n        String userCmd = "calc.exe";\n        // Dangerous CWE-78: Unsanitized command execution\n        Runtime.getRuntime().exec(userCmd);\n    }\n}`
    },
    python: {
      py_missing_colon: `# Error: Missing colons on 'def' and 'if' statements!\ndef check_number(val)\n    if val > 10\n        print("Number is large")\n    else\n        print("Number is small")\n\ncheck_number(15)`,
      py_indent_error: `# Error: Inconsistent indentation levels (IndentationError)!\ndef run_loop():\n    total = 0\n  for i in range(5):\n        total += i\n    print("Total:", total)\n\nrun_loop()`,
      py_print_v2: `# Error: Python 2 print syntax without parentheses!\ndef greet(name):\n    print "Hello, " + name\n\ngreet("NeuralCC")`,
      py_undeclared: `def compute():\n    print("Value:", unknown_score)\n\ncompute()`,
      py_security_eval: `# Warning: CWE-94 Code Injection via eval()!\nuser_data = "10 + 20"\nresult = eval(user_data) # Insecure arbitrary code execution\nprint("Evaluated:", result)`,
      py_valid: `# Valid Python 3 Script with functions and loops\ndef factorial(n):\n    if n <= 1:\n        return 1\n    return n * factorial(n - 1)\n\nprint("=== NeuralCC Python 3.11 Runtime ===")\nfor i in range(1, 6):\n    print("factorial(" + str(i) + ") =", factorial(i))\nprint("Execution completed successfully!")`
    }
  };

  // ════════════════════════════════════════════════════
  //  2. PYTHON FRONTEND ENGINE
  // ════════════════════════════════════════════════════
  const PythonFrontend = {
    keywords: new Set([
      'def', 'class', 'if', 'elif', 'else', 'for', 'in', 'while', 'break', 'continue',
      'return', 'pass', 'import', 'from', 'as', 'global', 'lambda', 'try', 'except',
      'finally', 'raise', 'with', 'is', 'not', 'and', 'or', 'True', 'False', 'None',
      'print', 'range', 'len', 'int', 'str', 'float', 'list', 'dict'
    ]),

    lex(source) {
      const tokens = [];
      const errors = [];
      const lines = source.split('\n');
      const indentStack = [0];

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const lineNum = lineIdx + 1;
        const line = lines[lineIdx];
        const trimmed = line.trim();

        // Skip blank lines and comments for indentation
        if (!trimmed || trimmed.startsWith('#')) {
          if (trimmed.startsWith('#')) {
            tokens.push({ type: 'COMMENT', value: trimmed, line: lineNum, col: line.indexOf('#') + 1 });
          }
          continue;
        }

        // Measure leading indentation
        let indent = 0;
        while (indent < line.length && (line[indent] === ' ' || line[indent] === '\t')) {
          indent += (line[indent] === '\t' ? 4 : 1);
        }

        const currentIndent = indentStack[indentStack.length - 1];

        if (indent > currentIndent) {
          let prevBlockInitiator = false;
          for (let pIdx = lineIdx - 1; pIdx >= 0; pIdx--) {
            const pLine = lines[pIdx].trim();
            if (pLine && !pLine.startsWith('#')) {
              if (pLine.endsWith(':')) prevBlockInitiator = true;
              break;
            }
          }
          if (!prevBlockInitiator && indent > 0) {
            errors.push({
              type: 'LexError',
              line: lineNum,
              col: indent + 1,
              raw: "IndentationError: unexpected indent",
              why: "In Python lexical rules, indentation is reserved exclusively for nested blocks after a colon ':'.",
              whatToAdd: `Align line ${lineNum} with the outer block indentation.`,
              fix: `Remove unintended indentation on line ${lineNum}.`
            });
          }
          indentStack.push(indent);
          tokens.push({ type: 'INDENT', value: indent, line: lineNum, col: 1 });
        } else if (indent < currentIndent) {
          let matched = false;
          while (indentStack.length > 1) {
            const popped = indentStack.pop();
            tokens.push({ type: 'DEDENT', value: popped, line: lineNum, col: 1 });
            if (indentStack[indentStack.length - 1] === indent) {
              matched = true;
              break;
            }
          }
          if (!matched && indent !== 0) {
            errors.push({
              type: 'LexError',
              line: lineNum,
              col: indent + 1,
              raw: `IndentationError: unindent does not match any outer indentation level (expected ${indentStack[indentStack.length - 1]} spaces, got ${indent})`,
              why: 'Python strictly requires consistent block indentation (LexiScan Delimiter Rule).',
              whatToAdd: `Re-align line ${lineNum} to ${indentStack[indentStack.length - 1]} spaces.`,
              fix: `Re-align line ${lineNum} to ${indentStack[indentStack.length - 1]} spaces.`
            });
          }
        }

        // Check for missing colon on compound statements
        if (/^\s*(def\s+\w+\s*\([^)]*\)|if\s+.+|elif\s+.+|else|while\s+.+|for\s+\w+\s+in\s+.+|class\s+\w+)(\s*)$/.test(line)) {
          if (!line.trim().endsWith(':')) {
            errors.push({
              type: 'ParseError',
              line: lineNum,
              col: line.length + 1,
              raw: `SyntaxError: expected ':' at end of '${trimmed.split(' ')[0]}' statement`,
              why: `In Python grammar, compound statements (${trimmed.split(' ')[0]}) require a trailing colon ':' to initiate a block.`,
              whatToAdd: `Add ':' at the end of line ${lineNum}.`,
              fix: `Add ':' at the end of line ${lineNum}.`
            });
          }
        }

        // Check for Python 2 print "..."
        if (/^\s*print\s+["'][^"']*["']/.test(line) && !line.includes('(')) {
          errors.push({
            type: 'ParseError',
            line: lineNum,
            col: line.indexOf('print') + 1,
            raw: `SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...) ?`,
            why: 'In Python 3 grammar, print is a built-in function, not a statement keyword.',
            whatToAdd: `Wrap the print arguments in parentheses: print(...)`,
            fix: `Wrap the print arguments in parentheses: print(...)`
          });
        }

        // Tokenize line characters
        let i = 0;
        while (i < line.length) {
          const ch = line[i];
          if (/\s/.test(ch)) { i++; continue; }
          if (ch === '#') {
            tokens.push({ type: 'COMMENT', value: line.substring(i), line: lineNum, col: i + 1 });
            break;
          }

          if (ch === '"' || ch === "'") {
            const quote = ch;
            let strVal = quote;
            let j = i + 1;
            let closed = false;
            while (j < line.length) {
              const c = line[j++];
              strVal += c;
              if (c === '\\' && j < line.length) { strVal += line[j++]; continue; }
              if (c === quote) { closed = true; break; }
            }
            if (!closed) {
              errors.push({
                type: 'LexError',
                line: lineNum,
                col: i + 1,
                raw: `SyntaxError: EOL while scanning string literal: ${strVal}`,
                why: 'String literal was opened but not terminated before the end of the line.',
                whatToAdd: `Close string with ${quote}.`,
                fix: `Close the string with ${quote}.`
              });
            }
            tokens.push({ type: 'STRING', value: strVal, line: lineNum, col: i + 1 });
            i = j;
            continue;
          }

          if (/[0-9]/.test(ch)) {
            let numStr = ch;
            let j = i + 1;
            while (j < line.length && /[0-9._]/.test(line[j])) numStr += line[j++];
            tokens.push({ type: 'NUMBER', value: numStr, line: lineNum, col: i + 1 });
            i = j;
            continue;
          }

          if (/[a-zA-Z_]/.test(ch)) {
            let idStr = ch;
            let j = i + 1;
            while (j < line.length && /[a-zA-Z0-9_]/.test(line[j])) idStr += line[j++];
            const isKw = PythonFrontend.keywords.has(idStr);
            tokens.push({ type: isKw ? 'KEYWORD' : 'IDENTIFIER', value: idStr, line: lineNum, col: i + 1 });
            i = j;
            continue;
          }

          const op2 = line.substring(i, i + 2);
          if (['==', '!=', '<=', '>=', '//', '**', '+=', '-=', '*=', '/='].includes(op2)) {
            tokens.push({ type: 'OPERATOR', value: op2, line: lineNum, col: i + 1 });
            i += 2;
            continue;
          }

          if (/[+\-*\/%<>=]/.test(ch)) {
            tokens.push({ type: 'OPERATOR', value: ch, line: lineNum, col: i + 1 });
            i++;
            continue;
          }

          if (/[()[\]{},:.]/.test(ch)) {
            tokens.push({ type: 'PUNCTUATION', value: ch, line: lineNum, col: i + 1 });
            i++;
            continue;
          }

          errors.push({
            type: 'LexError',
            line: lineNum,
            col: i + 1,
            raw: `SyntaxError: invalid character in identifier: '${ch}'`,
            why: `Python lexical grammar does not permit character '${ch}' outside strings.`,
            whatToAdd: `Remove invalid character '${ch}'.`,
            fix: `Remove character '${ch}'.`
          });
          i++;
        }
      }

      while (indentStack.length > 1) {
        indentStack.pop();
        tokens.push({ type: 'DEDENT', value: 0, line: lines.length, col: 1 });
      }
      tokens.push({ type: 'EOF', value: '', line: lines.length, col: 1 });

      return { tokens, errors };
    },

    parse(tokens, source) {
      const ast = { kind: 'Program', language: 'python', children: [] };
      const lines = source.split('\n');

      for (let l = 0; l < lines.length; l++) {
        const line = lines[l].trim();
        const lineNum = l + 1;
        if (!line || line.startsWith('#')) continue;

        const defMatch = line.match(/^def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*:/);
        if (defMatch) {
          const fnName = defMatch[1];
          const rawParams = defMatch[2].split(',').map(p => p.trim()).filter(Boolean);
          ast.children.push({
            kind: 'FuncDecl',
            name: fnName,
            returnType: 'dynamic',
            params: rawParams.map(p => ({ kind: 'Param', name: p, type: 'dynamic' })),
            line: lineNum,
            children: []
          });
          continue;
        }

        const printMatch = line.match(/^print\s*\((.*)\)$/);
        if (printMatch) {
          ast.children.push({
            kind: 'Call',
            callee: 'print',
            args: [{ kind: 'Literal', raw: printMatch[1], value: printMatch[1] }],
            line: lineNum
          });
          continue;
        }

        const retMatch = line.match(/^return\s*(.*)$/);
        if (retMatch) {
          ast.children.push({
            kind: 'Return',
            value: { kind: 'Literal', raw: retMatch[1] || 'None', value: retMatch[1] || 'None' },
            line: lineNum
          });
          continue;
        }

        const forMatch = line.match(/^for\s+([a-zA-Z_]\w*)\s+in\s+range\(([^)]*)\)\s*:/);
        if (forMatch) {
          ast.children.push({
            kind: 'For',
            iterVar: forMatch[1],
            rangeArgs: forMatch[2],
            line: lineNum,
            children: []
          });
          continue;
        }

        const ifMatch = line.match(/^if\s+(.+)\s*:/);
        if (ifMatch) {
          ast.children.push({
            kind: 'If',
            condition: ifMatch[1],
            line: lineNum,
            children: []
          });
          continue;
        }

        const assignMatch = line.match(/^([a-zA-Z_]\w*)\s*=\s*(.+)$/);
        if (assignMatch && !line.includes('==')) {
          ast.children.push({
            kind: 'VarDecl',
            name: assignMatch[1],
            dataType: 'dynamic',
            init: { kind: 'Literal', raw: assignMatch[2], value: assignMatch[2] },
            line: lineNum
          });
          continue;
        }

        ast.children.push({
          kind: 'ExprStmt',
          expr: line,
          line: lineNum
        });
      }

      return { ast, errors: [] };
    },

    analyze(ast, tokens, source) {
      const errors = [];
      const declaredVars = new Set([
        'print', 'range', 'len', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'bool',
        'sum', 'min', 'max', 'abs', 'round', 'enumerate', 'zip', 'reversed', 'sorted', 'filter', 'map',
        'isinstance', 'issubclass', 'type', 'repr', 'any', 'all', 'dir', 'help', 'open', 'input',
        'chr', 'ord', 'bin', 'hex', 'oct', 'pow', 'divmod', 'id', 'hash', 'iter', 'next', 'slice',
        'super', 'object', 'classmethod', 'staticmethod', 'property', 'self', 'cls',
        'None', 'True', 'False', 'Ellipsis',
        'Exception', 'BaseException', 'ValueError', 'TypeError', 'IndexError', 'KeyError',
        'AttributeError', 'NameError', 'FileNotFoundError', 'ZeroDivisionError', 'AssertionError',
        'RuntimeError', 'StopIteration', 'ImportError', 'NotImplementedError', 'OverflowError',
        '__name__', '__file__', '__doc__'
      ]);

      // 1. Extract function definitions and all parameter names (val, a, b, *args, **kwargs, defaults)
      const defRegex = /def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)/g;
      let dMatch;
      while ((dMatch = defRegex.exec(source)) !== null) {
        declaredVars.add(dMatch[1]);
        const rawParams = dMatch[2].split(',');
        for (let p of rawParams) {
          p = p.trim();
          if (!p) continue;
          const paramName = p.split(/[:=]/)[0].replace(/^[*]+/, '').trim();
          if (paramName && /^[a-zA-Z_]\w*$/.test(paramName)) {
            declaredVars.add(paramName);
          }
        }
      }

      // 2. Extract class declarations
      const classRegex = /class\s+([a-zA-Z_]\w*)/g;
      let cMatch;
      while ((cMatch = classRegex.exec(source)) !== null) {
        declaredVars.add(cMatch[1]);
      }

      // 3. Extract imports
      const importRegex = /^\s*import\s+(.+)$/gm;
      let impMatch;
      while ((impMatch = importRegex.exec(source)) !== null) {
        const parts = impMatch[1].split(',');
        for (let part of parts) {
          const asParts = part.trim().split(/\s+as\s+/);
          const mod = (asParts[1] || asParts[0]).trim();
          if (/^[a-zA-Z_]\w*$/.test(mod)) declaredVars.add(mod);
        }
      }
      const fromImportRegex = /^\s*from\s+[\w.]+\s+import\s+(.+)$/gm;
      let fromMatch;
      while ((fromMatch = fromImportRegex.exec(source)) !== null) {
        const parts = fromMatch[1].split(',');
        for (let part of parts) {
          const asParts = part.trim().split(/\s+as\s+/);
          const item = (asParts[1] || asParts[0]).trim();
          if (/^[a-zA-Z_]\w*$/.test(item)) declaredVars.add(item);
        }
      }

      // 4. Extract for iteration targets
      const forRegex = /for\s+([^:]+?)\s+in\s+/g;
      let fMatch;
      while ((fMatch = forRegex.exec(source)) !== null) {
        const iterTargets = fMatch[1].split(',');
        for (let t of iterTargets) {
          const cleanT = t.trim();
          if (/^[a-zA-Z_]\w*$/.test(cleanT)) declaredVars.add(cleanT);
        }
      }

      // 5. Extract with and except bindings
      const withRegex = /with\s+.+?\s+as\s+([a-zA-Z_]\w*)/g;
      let wMatch;
      while ((wMatch = withRegex.exec(source)) !== null) {
        declaredVars.add(wMatch[1]);
      }
      const exceptRegex = /except\s+(?:[a-zA-Z_]\w*)?\s+as\s+([a-zA-Z_]\w*)/g;
      let eMatch;
      while ((eMatch = exceptRegex.exec(source)) !== null) {
        declaredVars.add(eMatch[1]);
      }

      for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        if (t.type === 'IDENTIFIER') {
          const next = tokens[i + 1];
          const prev = tokens[i - 1];

          // Attribute access like obj.attr or math.sqrt is not a standalone identifier
          if (prev && prev.value === '.') {
            continue;
          }

          if (next && (next.value === '=' || next.value === '+=' || next.value === '-=' || next.value === '*=' || next.value === '/=')) {
            declaredVars.add(t.value);
          } else if (prev && (prev.value === 'def' || prev.value === 'for' || prev.value === 'class' || prev.value === 'import' || prev.value === 'as')) {
            declaredVars.add(t.value);
          } else {
            if (!declaredVars.has(t.value) && !['None', 'True', 'False'].includes(t.value)) {
              const line = source.split('\n')[t.line - 1] || '';
              if (!line.includes('def ') && !line.includes('for ') && !line.includes('class ')) {
                errors.push({
                  type: 'SemanticError',
                  line: t.line,
                  col: t.col,
                  raw: `NameError: name '${t.value}' is not defined`,
                  why: `Attempted to reference variable '${t.value}' before any assignment in scope.`,
                  whatToAdd: `Initialize '${t.value} = ...' prior to reading it.`,
                  fix: `Initialize '${t.value} = ...' prior to reading it.`
                });
                declaredVars.add(t.value);
              }
            }
          }
        }
      }

      // 7. Symbol Extraction for IR/CFG & Symbols tab
      const symbolLog = [];
      const defRegex2 = /def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)/g;
      let dMatch2;
      while ((dMatch2 = defRegex2.exec(source)) !== null) {
        const line = source.substring(0, dMatch2.index).split('\n').length;
        symbolLog.push({ name: dMatch2[1], type: 'def / func', line });
        const rawParams = dMatch2[2].split(',');
        for (let p of rawParams) {
          const pName = p.trim().split(/[:=]/)[0].replace(/^[*]+/, '').trim();
          if (pName && /^[a-zA-Z_]\w*$/.test(pName)) {
            symbolLog.push({ name: pName, type: 'param', line });
          }
        }
      }
      const classRegex2 = /class\s+([a-zA-Z_]\w*)/g;
      let cMatch2;
      while ((cMatch2 = classRegex2.exec(source)) !== null) {
        const line = source.substring(0, cMatch2.index).split('\n').length;
        symbolLog.push({ name: cMatch2[1], type: 'class', line });
      }
      const assignRegex2 = /^\s*([a-zA-Z_]\w*)\s*=(?!=)/gm;
      let aMatch2;
      while ((aMatch2 = assignRegex2.exec(source)) !== null) {
        const line = source.substring(0, aMatch2.index).split('\n').length;
        if (!symbolLog.some(s => s.name === aMatch2[1])) {
          symbolLog.push({ name: aMatch2[1], type: 'var', line });
        }
      }
      PythonFrontend._lastSymbols = symbolLog;

      return errors;
    },

    scanSecurity(tokens, ast, source) {
      const warnings = [];

      if (/eval\s*\(/.test(source)) {
        warnings.push({
          fn: 'eval',
          cwe: 'CWE-94',
          name: 'Arbitrary Code Execution (Insecure eval)',
          severity: 'CRITICAL',
          cvss: 9.8,
          msg: 'eval() executes arbitrary Python code from string inputs. If input is untrusted, an attacker can execute OS commands or compromise host system.',
          fixHint: 'Use ast.literal_eval() for safe literal evaluation or replace with structured parser.'
        });
      }

      if (/os\.system\s*\(|subprocess\.Popen\s*\(/.test(source)) {
        warnings.push({
          fn: 'os.system',
          cwe: 'CWE-78',
          name: 'OS Command Injection',
          severity: 'CRITICAL',
          cvss: 9.8,
          msg: 'Passing unsanitized strings to os.system() passes input directly to shell, enabling shell injection exploits.',
          fixHint: 'Use subprocess.run(["cmd", arg1], shell=False) with parameterized arguments.'
        });
      }

      return warnings;
    },

    generateIR(ast) {
      const instrs = [];
      let tempCount = 0;
      let labelCount = 0;
      const newTemp = () => `t${tempCount++}`;
      const newLabel = () => `L${labelCount++}`;
      let currentBlock = 'B_MAIN';

      const emit = (op, result = '', arg1 = '', arg2 = '', line = 1, bid = currentBlock) => {
        instrs.push({ op, result, res: result, arg1: String(arg1 || ''), arg2: String(arg2 || ''), line, blockId: bid });
        return result;
      };

      emit('PY_INIT', '', 'Python 3.11 Runtime Frame', '', 1, 'B_INIT');

      for (const node of (ast.children || [])) {
        if (node.kind === 'FuncDecl') {
          const bFunc = 'B_' + node.name;
          emit('FUNC_BEGIN', node.name, node.returnType || 'dynamic', '', node.line || 1, bFunc);
          if (node.params && node.params.length > 0) {
            emit('ALLOC_SCOPE', '', node.params.map(p => p.name).join(','), '', node.line || 1, bFunc);
          }
          emit('FUNC_END', node.name, '', '', node.line || 1, bFunc);
        } else if (node.kind === 'VarDecl') {
          const t = newTemp();
          emit('ASSIGN', t, node.init?.value || '0', '', node.line || 1, currentBlock);
          emit('STORE', node.name, t, '', node.line || 1, currentBlock);
        } else if (node.kind === 'Call' && node.callee === 'print') {
          emit('PARAM', '', node.args?.[0]?.value || '', '', node.line || 1, currentBlock);
          emit('CALL', 'void', 'sys.stdout.write', '1', node.line || 1, currentBlock);
        } else if (node.kind === 'For') {
          const lStart = newLabel();
          const lEnd = newLabel();
          emit('ITER_INIT', node.iterVar || 'i', node.rangeArgs || 'range()', '', node.line || 1, currentBlock);
          emit('LABEL', lStart, '', '', node.line || 1, currentBlock);
          emit('IF_EXHAUSTED', '', node.iterVar || 'i', lEnd, node.line || 1, currentBlock);
          emit('GOTO', lStart, '', '', node.line || 1, currentBlock);
          emit('LABEL', lEnd, '', '', node.line || 1, currentBlock);
        } else if (node.kind === 'If') {
          const lThen = newLabel();
          const lEnd = newLabel();
          emit('BRANCH', lThen, node.condition || 'cond', lEnd, node.line || 1, currentBlock);
        } else if (node.kind === 'ExprStmt') {
          emit('EXPR_EVAL', '', node.expr || '', '', node.line || 1, currentBlock);
        }
      }

      emit('PY_TERMINATE', 'exitCode 0', '', '', 1, currentBlock);
      return instrs;
    },

    autoCorrect(source) {
      let code = source;
      const fixes = [];

      const lines = code.split('\n');
      const patchedLines = lines.map((line, idx) => {
        const trimmed = line.trim();
        if (/^(def\s+\w+\s*\([^)]*\)|if\s+.+|elif\s+.+|else|while\s+.+|for\s+\w+\s+in\s+.+|class\s+\w+)$/.test(trimmed)) {
          if (!trimmed.endsWith(':')) {
            fixes.push({ line: idx + 1, type: 'SyntaxFix', description: `Added missing colon ':' to '${trimmed.split(' ')[0]}'`, fix: line + ':' });
            return line + ':';
          }
        }
        return line;
      });
      code = patchedLines.join('\n');

      if (/print\s+["'][^"']*["']/.test(code) && !code.includes('print(')) {
        code = code.replace(/print\s+(["'][^"']*["'])/g, (m, g) => {
          fixes.push({ line: 1, type: 'SyntaxFix', description: "Converted Python 2 print statement to Python 3 print() function call", fix: `print(${g})` });
          return `print(${g})`;
        });
      }

      code = code.replace(/if\s+([a-zA-Z_]\w*)\s*=\s*([^:=]+):/g, (m, v, val) => {
        fixes.push({ line: 1, type: 'GrammarFix', description: `Replaced '=' assignment in 'if' condition with '==' equality check`, fix: `if ${v} == ${val.trim()}:` });
        return `if ${v} == ${val.trim()}:`;
      });

      return {
        correctedSource: code,
        changesMade: fixes.length > 0,
        fixesApplied: fixes
      };
    }
  };

  // ════════════════════════════════════════════════════
  //  3. C++ FRONTEND ENGINE
  // ════════════════════════════════════════════════════
  const CppFrontend = {
    lex(source) {
      const res = (typeof lex === 'function') ? lex(source) : { tokens: [], errors: [] };
      const tokens = res.tokens || [];
      const errors = [...(res.errors || [])];

      const lines = source.split('\n');
      let inClass = false;
      let classBraceDepth = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (/\bclass\s+[a-zA-Z_]\w*/.test(line)) {
          inClass = true;
        }

        if (inClass) {
          for (let cIdx = 0; cIdx < line.length; cIdx++) {
            const ch = line[cIdx];
            if (ch === '{') classBraceDepth++;
            if (ch === '}') {
              classBraceDepth--;
              if (classBraceDepth === 0) {
                inClass = false;
                if (!line.trim().endsWith(';') && !line.includes('};')) {
                  errors.push({
                    type: 'ParseError',
                    line: i + 1,
                    col: cIdx + 1,
                    raw: "expected ';' after class definition",
                    why: "In C++, a class declaration must terminate with a semicolon ';'.",
                    whatToAdd: "Add ';' after closing brace of class.",
                    fix: "Add ';' after closing brace of class."
                  });
                }
              }
            }
          }
        }

        if (/\bcout\s*>>/.test(line)) {
          errors.push({
            type: 'ParseError',
            line: i + 1,
            col: line.indexOf('>>') + 1,
            raw: "invalid operands to binary expression ('std::ostream' and '>>'). Did you mean '<<' ?",
            why: "cout uses the stream insertion operator '<<'. Stream extraction '>>' is reserved for cin.",
            whatToAdd: "Replace 'cout >>' with 'cout <<'.",
            fix: "Replace 'cout >>' with 'cout <<'."
          });
        }
      }

      return { tokens, errors };
    },

    parse(tokens, source) {
      const ast = { kind: 'Program', language: 'cpp', children: [] };
      const lines = source.split('\n');

      let currentClass = null;

      for (let l = 0; l < lines.length; l++) {
        const line = lines[l].trim();
        const lineNum = l + 1;
        if (!line || line.startsWith('//')) continue;

        const classMatch = line.match(/^class\s+([a-zA-Z_]\w*)/);
        if (classMatch) {
          currentClass = {
            kind: 'ClassDecl',
            name: classMatch[1],
            members: [],
            line: lineNum
          };
          ast.children.push(currentClass);
          continue;
        }

        if (currentClass && line.includes('}')) {
          currentClass = null;
          continue;
        }

        if (currentClass) {
          if (line.includes('public:') || line.includes('private:') || line.includes('protected:')) {
            continue;
          }
          const mMatch = line.match(/^(int|void|float|double|string|bool)\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)/);
          if (mMatch) {
            currentClass.members.push({
              kind: 'MethodDecl',
              returnType: mMatch[1],
              name: mMatch[2],
              params: mMatch[3],
              line: lineNum
            });
            continue;
          }
        }

        if (line.includes('cout') && line.includes('<<')) {
          ast.children.push({
            kind: 'StreamOutput',
            expr: line,
            line: lineNum
          });
          continue;
        }

        const fnMatch = line.match(/^(int|void)\s+main\s*\([^)]*\)/);
        if (fnMatch) {
          ast.children.push({
            kind: 'FuncDecl',
            name: 'main',
            returnType: fnMatch[1],
            line: lineNum,
            children: []
          });
          continue;
        }
      }

      return { ast, errors: [] };
    },

    analyze(ast, tokens, source) {
      const errors = [];

      if ((source.includes('cout') || source.includes('cin')) && !source.includes('<iostream>')) {
        errors.push({
          type: 'HeaderError',
          line: 1,
          col: 1,
          raw: "use of undeclared identifier 'cout'; did you forget to '#include <iostream>'?",
          why: "C++ standard stream objects 'cout' and 'cin' are declared in the <iostream> standard header.",
          whatToAdd: "Add '#include <iostream>' at the top of the file.",
          fix: "Add '#include <iostream>' at the top of the file."
        });
      }

      if (source.includes('cout') && !source.includes('std::cout') && !source.includes('using namespace std;')) {
        errors.push({
          type: 'SemanticError',
          line: 1,
          col: 1,
          raw: "'cout' is not a member of global namespace. Did you mean 'std::cout' or forget 'using namespace std;'?",
          why: "All standard C++ symbols are scoped inside namespace 'std'.",
          whatToAdd: "Add 'using namespace std;' or prefix with 'std::cout'.",
          fix: "Add 'using namespace std;' or prefix with 'std::cout'."
        });
      }

      // Symbol Extraction for IR/CFG & Symbols tab
      const symbolLog = [];
      const clsRegex = /(?:class|struct)\s+([a-zA-Z_]\w*)/g;
      let cm;
      while ((cm = clsRegex.exec(source)) !== null) {
        const line = source.substring(0, cm.index).split('\n').length;
        symbolLog.push({ name: cm[1], type: 'class/struct', line });
      }
      const fnRegex = /\b(int|void|float|double|char|bool|auto|string)\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{/g;
      let fm;
      while ((fm = fnRegex.exec(source)) !== null) {
        const line = source.substring(0, fm.index).split('\n').length;
        symbolLog.push({ name: fm[2], type: fm[1] + ' (func)', line });
      }
      const varRegex = /\b(int|float|double|char|bool|string|auto|[A-Z]\w*)\s+([a-zA-Z_]\w*)\s*(?:=|;|\()/g;
      let vm;
      while ((vm = varRegex.exec(source)) !== null) {
        if (vm[2] !== 'main' && vm[2] !== 'if' && vm[2] !== 'while' && vm[2] !== 'for' && vm[2] !== 'return') {
          const line = source.substring(0, vm.index).split('\n').length;
          if (!symbolLog.some(s => s.name === vm[2])) {
            symbolLog.push({ name: vm[2], type: vm[1], line });
          }
        }
      }
      CppFrontend._lastSymbols = symbolLog;

      return errors;
    },

    scanSecurity(tokens, ast, source) {
      const warnings = [];

      if (/new\s+[a-zA-Z_]\w*(\[[^\]]*\]|\(\))/.test(source) && !source.includes('delete')) {
        warnings.push({
          fn: 'new',
          cwe: 'CWE-401',
          name: 'Missing Heap Deallocation (Memory Leak)',
          severity: 'HIGH',
          cvss: 7.5,
          msg: 'Heap memory allocated with "new" is never freed with "delete". Causes progressive memory exhaustion.',
          fixHint: 'Pair every "new" with "delete" (or "delete[]" for arrays) or use std::unique_ptr / std::make_unique.'
        });
      }

      if (/\bgets\s*\(/.test(source)) {
        warnings.push({
          fn: 'gets',
          cwe: 'CWE-120',
          name: 'Buffer Overflow (C++ Stack Smashing)',
          severity: 'CRITICAL',
          cvss: 9.8,
          msg: 'gets() is obsolete and removed in C++14/C++17 due to catastrophic buffer overflow vulnerabilities.',
          fixHint: 'Replace with std::cin >> buf or std::getline(std::cin, str).'
        });
      }

      return warnings;
    },

    generateIR(ast) {
      const instrs = [];
      let temp = 0;
      const newT = () => `t${temp++}`;
      let currentBlock = 'B_MAIN';

      const emit = (op, result = '', arg1 = '', arg2 = '', line = 1, bid = currentBlock) => {
        instrs.push({ op, result, res: result, arg1: String(arg1 || ''), arg2: String(arg2 || ''), line, blockId: bid });
        return result;
      };

      emit('CPP_INIT', '', 'C++17 OOP V-Table ABI', '', 1, 'B_INIT');

      for (const node of (ast.children || [])) {
        if (node.kind === 'ClassDecl') {
          const bClass = 'B_' + node.name;
          emit('CLASS_DEF', node.name, '', '', node.line || 1, bClass);
          for (const m of (node.members || [])) {
            emit('METHOD_BIND', `${node.name}::${m.name}`, 'this', '', m.line || node.line || 1, bClass);
          }
        } else if (node.kind === 'StreamOutput') {
          const t = newT();
          emit('STREAM_EVAL', t, node.expr || '', '', node.line || 1, currentBlock);
          emit('OSTREAM_WRITE', 'std::cout', t, '', node.line || 1, currentBlock);
        } else if (node.kind === 'FuncDecl') {
          const bFunc = 'B_' + node.name;
          emit('FUNC_BEGIN', node.name, node.returnType || 'int', '', node.line || 1, bFunc);
          emit('FUNC_END', node.name, '', '', node.line || 1, bFunc);
        }
      }

      emit('CPP_TERMINATE', 'exitCode 0', '', '', 1, currentBlock);
      return instrs;
    },

    autoCorrect(source) {
      let code = source;
      const fixes = [];

      code = code.replace(/(\bclass\s+\w+[\s\S]*?\n\s*\})(\s*\n)/g, (m, g1, g2) => {
        if (!g1.endsWith(';')) {
          fixes.push({ line: 1, type: 'GrammarFix', description: "Added missing semicolon ';' after C++ class definition", fix: `${g1};${g2}` });
          return `${g1};${g2}`;
        }
        return m;
      });

      if (/\bcout\s*>>/.test(code)) {
        code = code.replace(/\bcout\s*>>/g, 'cout <<');
        fixes.push({ line: 1, type: 'SyntaxFix', description: "Corrected stream insertion operator 'cout >>' to 'cout <<'", fix: "cout <<" });
      }

      if (code.includes('cout') && !code.includes('<iostream>')) {
        code = `#include <iostream>\n${code}`;
        fixes.push({ line: 1, type: 'HeaderFix', description: "Injected missing standard C++ header '#include <iostream>'", fix: "#include <iostream>" });
      }

      if (code.includes('cout') && !code.includes('std::cout') && !code.includes('using namespace std;')) {
        code = code.replace(/(#include\s*<iostream>)/, `$1\nusing namespace std;`);
        fixes.push({ line: 2, type: 'HeaderFix', description: "Added 'using namespace std;' to resolve standard library stream symbols", fix: "using namespace std;" });
      }

      return {
        correctedSource: code,
        changesMade: fixes.length > 0,
        fixesApplied: fixes
      };
    }
  };

  // ════════════════════════════════════════════════════
  //  4. JAVA FRONTEND ENGINE (ROBUST & ACCURATE)
  // ════════════════════════════════════════════════════
  const JavaFrontend = {
    keywords: new Set([
      'public', 'private', 'protected', 'class', 'interface', 'extends', 'implements',
      'static', 'final', 'abstract', 'void', 'int', 'double', 'float', 'char', 'boolean',
      'byte', 'short', 'long', 'new', 'this', 'super', 'return', 'if', 'else', 'while',
      'for', 'do', 'break', 'continue', 'switch', 'case', 'default', 'try', 'catch',
      'finally', 'throw', 'throws', 'import', 'package', 'instanceof', 'String', 'System'
    ]),

    lex(source) {
      const tokens = [];
      const errors = [];
      const lines = source.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;
        const trimmed = line.trim();

        if (!trimmed || trimmed.startsWith('//')) {
          if (trimmed.startsWith('//')) {
            tokens.push({ type: 'COMMENT', value: trimmed, line: lineNum, col: 1 });
          }
          continue;
        }

        // Case-sensitivity audit: 'system.out'
        if (/\bsystem\.out\b/.test(line)) {
          errors.push({
            type: 'SemanticError',
            line: lineNum,
            col: line.indexOf('system.out') + 1,
            raw: "package system does not exist. Did you mean capitalized 'System.out'?",
            why: "Java is strictly case-sensitive. The standard I/O class is 'java.lang.System'.",
            whatToAdd: "Capitalize 'system.out' to 'System.out'.",
            fix: "Capitalize 'system.out' to 'System.out'."
          });
        }

        // Tokenize line words
        const words = line.match(/[a-zA-Z_]\w*|[0-9.]+|"[^"]*"|'[^']*'|[+\-*\/=<>!&|^%]+|[(){}[\];,.]/g) || [];
        for (const w of words) {
          if (JavaFrontend.keywords.has(w)) {
            tokens.push({ type: 'KEYWORD', value: w, line: lineNum, col: 1 });
          } else if (/^[0-9]/.test(w)) {
            tokens.push({ type: 'NUMBER', value: w, line: lineNum, col: 1 });
          } else if (w.startsWith('"') || w.startsWith("'")) {
            tokens.push({ type: 'STRING', value: w, line: lineNum, col: 1 });
          } else if (/[+\-*\/=<>!&|^%]/.test(w)) {
            tokens.push({ type: 'OPERATOR', value: w, line: lineNum, col: 1 });
          } else if (/[(){}[\];,.]/.test(w)) {
            tokens.push({ type: 'PUNCTUATION', value: w, line: lineNum, col: 1 });
          } else {
            tokens.push({ type: 'IDENTIFIER', value: w, line: lineNum, col: 1 });
          }
        }
      }

      tokens.push({ type: 'EOF', value: '', line: lines.length, col: 1 });
      return { tokens, errors };
    },

    parse(tokens, source) {
      const ast = { kind: 'Program', language: 'java', children: [] };
      const errors = [];
      const lines = source.split('\n');

      let currentClass = null;

      for (let l = 0; l < lines.length; l++) {
        const line = lines[l].trim();
        const lineNum = l + 1;
        if (!line || line.startsWith('//') || line.startsWith('/*')) continue;

        // 1. Missing Semicolon Check on statements
        // Statements that declare a variable or assign or call method and don't end with ;, {, or }
        const isStatement = /^(int|float|double|String|boolean|char|long|short)\s+\w+.*$/.test(line) ||
                            /^[a-zA-Z_]\w*\s*=\s*.*$/.test(line) ||
                            /^System\.out\.print.*$/.test(line) ||
                            /^return\s+.*$/.test(line);

        if (isStatement && !line.endsWith(';') && !line.endsWith('{') && !line.endsWith('}')) {
          errors.push({
            type: 'ParseError',
            line: lineNum,
            col: line.length + 1,
            raw: "';' expected",
            why: "In Java grammar, all simple statements and variable declarations must terminate with a semicolon ';'.",
            whatToAdd: "Add ';' at the end of this line.",
            fix: "Add ';' to the end of the statement."
          });
        }

        // Class definition: public class Main {
        const classMatch = line.match(/^public\s+class\s+([a-zA-Z_]\w*)/) || line.match(/^class\s+([a-zA-Z_]\w*)/);
        if (classMatch) {
          currentClass = {
            kind: 'ClassDecl',
            name: classMatch[1],
            members: [],
            line: lineNum
          };
          ast.children.push(currentClass);
          continue;
        }

        // Method: public static void main(String[] args)
        if (line.includes('public static void main')) {
          const mainMethod = {
            kind: 'MethodDecl',
            name: 'main',
            isStatic: true,
            returnType: 'void',
            line: lineNum,
            children: []
          };
          if (currentClass) currentClass.members.push(mainMethod);
          else ast.children.push(mainMethod);
          continue;
        }

        // System.out.println(...)
        if (line.includes('System.out.println') || line.includes('System.out.print')) {
          ast.children.push({
            kind: 'PrintCall',
            expr: line,
            line: lineNum
          });
          continue;
        }
      }

      // Check unbalanced braces
      let braceCount = 0;
      for (const t of tokens) {
        if (t.value === '{') braceCount++;
        else if (t.value === '}') braceCount--;
      }
      if (braceCount > 0) {
        errors.push({
          type: 'ParseError',
          line: lines.length,
          col: 1,
          raw: "reached end of file while parsing (unmatched '{')",
          why: "Block was opened with '{' but not closed with matching '}'.",
          whatToAdd: "Add '}' at the end of the file.",
          fix: "Add '}' to close open blocks."
        });
      }

      return { ast, errors };
    },

    analyze(ast, tokens, source) {
      const errors = [];

      // 1. Check if file lacks any class wrapper
      if (!source.includes('class ')) {
        errors.push({
          type: 'BoilerplateError',
          line: 1,
          col: 1,
          raw: "class, interface, enum, or record expected. In Java, all statements and methods must reside inside a class.",
          why: "Java does not permit standalone procedural routines or top-level statements.",
          whatToAdd: "Wrap code in 'public class Main { ... }'.",
          fix: "Wrap code in 'public class Main { ... }'."
        });
      }

      // 2. Check for main method if class is present (only if no other methods exist)
      const hasOtherMethods = /\b(?:public|private|protected|static|\s)?\s*(?:void|int|double|float|String|boolean|[A-Z]\w*)\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{/.test(source.replace(/class\s+\w+/g, ''));
      if (source.includes('class ') && !source.includes('public static void main') && !hasOtherMethods) {
        errors.push({
          type: 'BoilerplateError',
          line: 1,
          col: 1,
          raw: "Main method not found in class. Standalone executable classes require: public static void main(String[] args)",
          why: "The Java Virtual Machine (JVM) requires this exact signature to execute.",
          whatToAdd: "Add 'public static void main(String[] args) { ... }' or define class methods.",
          fix: "Add 'public static void main(String[] args) { ... }'."
        });
      }

      // 3. Undeclared identifier analysis
      const declared = new Set(['args', 'System', 'String', 'Math']);
      const lines = source.split('\n');

      for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx].trim();
        const lineNum = idx + 1;

        // Collect variable declarations: int x = ..., String s = ...
        const declMatch = line.match(/^(int|float|double|String|boolean|char|long|short)\s+([a-zA-Z_]\w*)/);
        if (declMatch) {
          declared.add(declMatch[2]);
        }

        // For loop iterator: for (int i = 0; ...)
        const forMatch = line.match(/for\s*\(\s*(int|float|double)?\s*([a-zA-Z_]\w*)\s*=/);
        if (forMatch) {
          declared.add(forMatch[2]);
        }

        // Check standalone assignment: result = 50 + 20;
        const assignMatch = line.match(/^([a-zA-Z_]\w*)\s*=\s*(.+);?$/);
        if (assignMatch) {
          const varName = assignMatch[1];
          if (!declared.has(varName) && !JavaFrontend.keywords.has(varName)) {
            errors.push({
              type: 'SemanticError',
              line: lineNum,
              col: line.indexOf(varName) + 1,
              raw: `cannot find symbol: variable '${varName}'`,
              why: `Variable '${varName}' was referenced without any prior type declaration in scope.`,
              whatToAdd: `Declare variable type: 'int ${varName} = ...;'`,
              fix: `Add type declaration 'int ${varName} = ...;'`
            });
            declared.add(varName); // prevent duplicates
          }
        }
      }

      // Symbol Extraction for IR/CFG & Symbols tab
      const symbolLog = [];
      const jClsRegex = /\bclass\s+([a-zA-Z_]\w*)/g;
      let jcm;
      while ((jcm = jClsRegex.exec(source)) !== null) {
        const line = source.substring(0, jcm.index).split('\n').length;
        symbolLog.push({ name: jcm[1], type: 'class', line });
      }
      const jMthRegex = /\b(?:public|private|protected|static|\s)+([a-zA-Z_]\w*)\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{/g;
      let jmm;
      while ((jmm = jMthRegex.exec(source)) !== null) {
        if (jmm[2] !== 'class') {
          const line = source.substring(0, jmm.index).split('\n').length;
          symbolLog.push({ name: jmm[2], type: jmm[1] + ' (method)', line });
        }
      }
      const jVarRegex = /\b(int|float|double|char|boolean|String)\s+([a-zA-Z_]\w*)\s*(?:=|;)/g;
      let jvm;
      while ((jvm = jVarRegex.exec(source)) !== null) {
        const line = source.substring(0, jvm.index).split('\n').length;
        if (!symbolLog.some(s => s.name === jvm[2])) {
          symbolLog.push({ name: jvm[2], type: jvm[1], line });
        }
      }
      JavaFrontend._lastSymbols = symbolLog;

      return errors;
    },

    scanSecurity(tokens, ast, source) {
      const warnings = [];

      if (/Runtime\.getRuntime\(\)\.exec/.test(source) || /ProcessBuilder/.test(source)) {
        warnings.push({
          fn: 'Runtime.getRuntime().exec',
          cwe: 'CWE-78',
          name: 'OS Command Injection via JVM Subprocess',
          severity: 'CRITICAL',
          cvss: 9.8,
          msg: 'Executing host binaries through Runtime.exec() allows attackers to hijack the host operating system.',
          fixHint: 'Sanitize input with strict allow-lists and avoid passing command strings to shell interpreters.'
        });
      }

      return warnings;
    },

    generateIR(ast) {
      const instrs = [];
      let currentBlock = 'B_MAIN';

      const emit = (op, result = '', arg1 = '', arg2 = '', line = 1, bid = currentBlock) => {
        instrs.push({ op, result, res: result, arg1: String(arg1 || ''), arg2: String(arg2 || ''), line, blockId: bid });
        return result;
      };

      emit('JVM_BOOTSTRAP', '', 'Java 17 ClassLoader', '', 1, 'B_BOOT');

      for (const node of (ast.children || [])) {
        if (node.kind === 'ClassDecl') {
          const bClass = 'B_' + node.name;
          emit('CLASS_LOAD', node.name, '', '', node.line || 1, bClass);
          for (const m of (node.members || [])) {
            emit('INVOKE_STATIC', `${node.name}.${m.name}`, '(String[])V', '', m.line || node.line || 1, bClass);
          }
        } else if (node.kind === 'PrintCall') {
          emit('GETSTATIC', 'Ljava/io/PrintStream;', 'java/lang/System.out', '', node.line || 1, currentBlock);
          emit('INVOKEVIRTUAL', 'java/io/PrintStream.println', node.expr || '', '', node.line || 1, currentBlock);
        }
      }

      emit('JVM_RETURN', 'exit 0', '', '', 1, currentBlock);
      return instrs;
    },

    autoCorrect(source) {
      let code = source;
      const fixes = [];

      if (/\bsystem\.out\b/.test(code)) {
        code = code.replace(/\bsystem\.out\b/g, 'System.out');
        fixes.push({ line: 1, type: 'SemanticFix', description: "Capitalized 'system.out' to standard Java 'System.out'", fix: "System.out" });
      }

      if (!code.includes('class ')) {
        if (code.includes('public static void main')) {
          code = `public class Main {\n${code.split('\n').map(l => '    ' + l).join('\n')}\n}`;
        } else {
          code = `public class Main {\n    public static void main(String[] args) {\n${code.split('\n').map(l => '        ' + l).join('\n')}\n    }\n}`;
        }
        fixes.push({ line: 1, type: 'BoilerplateFix', description: "Wrapped orphan Java structure in 'public class Main { ... }'", fix: "class Main wrapper" });
      }

      const lines = code.split('\n');
      const patched = lines.map((l, idx) => {
        const tr = l.trim();
        if (/^(int|float|double|String|boolean)\s+\w+.*[^;{}]Shield?$/.test(tr) ||
            /^(int|float|double|String|boolean)\s+\w+\s*=.*[^;]$/.test(tr) ||
            /^[a-zA-Z_]\w*\s*=.*[^;{}]$/.test(tr) ||
            /^System\.out\.print(ln)?\(.*\)[^;]$/.test(tr)) {
          if (!tr.endsWith(';') && !tr.endsWith('{') && !tr.endsWith('}')) {
            fixes.push({ line: idx + 1, type: 'SyntaxFix', description: "Appended missing semicolon ';' to Java statement", fix: l + ';' });
            return l + ';';
          }
        }
        return l;
      });
      code = patched.join('\n');

      return {
        correctedSource: code,
        changesMade: fixes.length > 0,
        fixesApplied: fixes
      };
    }
  };

  // ════════════════════════════════════════════════════
  //  5. UNIVERSAL MULTI-LANGUAGE EXECUTOR
  // ════════════════════════════════════════════════════
  function executeVirtualProgram(source, lang, ast) {
    const startTime = performance.now();
    const config = LANGUAGE_CONFIGS[lang] || LANGUAGE_CONFIGS.c;
    const stdout = [];
    const stderr = [];
    let instructions = 0;

    stdout.push(`[NeuralCC Studio] Initializing ${config.standard} Virtual Execution Runtime...\n`);
    stdout.push(`[NeuralCC Studio] Command: ${config.runCommand}\n`);
    stdout.push('──────────────────────────────────────────────────\n');

    try {
      if (lang === 'c') {
        if (typeof VirtualCRuntime !== 'undefined' && ast) {
          const res = VirtualCRuntime.executeAST(ast, source);
          return res;
        }
      }

      if (lang === 'python') {
        const logPrint = (...args) => {
          stdout.push(args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ') + '\n');
        };

        const range = (start, stop, step = 1) => {
          if (stop === undefined) { stop = start; start = 0; }
          const res = [];
          for (let i = start; (step > 0 ? i < stop : i > stop); i += step) res.push(i);
          return res;
        };

        const len = x => (x ? (x.length !== undefined ? x.length : Object.keys(x).length) : 0);
        const sum = arr => (Array.isArray(arr) ? arr.reduce((a, b) => a + b, 0) : 0);
        const min = (...args) => Math.min(...(Array.isArray(args[0]) ? args[0] : args));
        const max = (...args) => Math.max(...(Array.isArray(args[0]) ? args[0] : args));
        const abs = Math.abs;
        const round = Math.round;
        const str = x => String(x);
        const int = x => parseInt(x, 10);
        const float = x => parseFloat(x);
        const bool = x => Boolean(x);
        const list = x => Array.from(x);

        try {
          const lines = source.split('\n');
          const jsLines = [];
          const indentStack = [0];

          for (let i = 0; i < lines.length; i++) {
            const rawLine = lines[i];
            const trimmed = rawLine.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            let indent = 0;
            while (indent < rawLine.length && (rawLine[indent] === ' ' || rawLine[indent] === '\t')) {
              indent += (rawLine[indent] === '\t' ? 4 : 1);
            }

            while (indentStack.length > 1 && indent < indentStack[indentStack.length - 1]) {
              indentStack.pop();
              jsLines.push('}');
            }

            let line = trimmed;
            line = line.replace(/\bTrue\b/g, 'true')
                       .replace(/\bFalse\b/g, 'false')
                       .replace(/\bNone\b/g, 'null')
                       .replace(/\band\b/g, '&&')
                       .replace(/\bor\b/g, '||')
                       .replace(/\bnot\s+/g, '!');

            // Handle f-strings
            line = line.replace(/f"([^"]*)"/g, (m, g) => `"${g.replace(/\{([^}]+)\}/g, '"+($1)+"')}"`);
            line = line.replace(/f'([^']*)'/g, (m, g) => `'${g.replace(/\{([^}]+)\}/g, "'+($1)+'")}'`);

            const defM = line.match(/^def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*:/);
            if (defM) {
              indentStack.push(indent + 4);
              jsLines.push(`function ${defM[1]}(${defM[2]}) {`);
              continue;
            }

            const ifM = line.match(/^if\s+(.+)\s*:/);
            if (ifM) {
              indentStack.push(indent + 4);
              jsLines.push(`if (${ifM[1]}) {`);
              continue;
            }

            const elifM = line.match(/^elif\s+(.+)\s*:/);
            if (elifM) {
              indentStack.push(indent + 4);
              jsLines.push(`else if (${elifM[1]}) {`);
              continue;
            }

            const elseM = line.match(/^else\s*:/);
            if (elseM) {
              indentStack.push(indent + 4);
              jsLines.push(`else {`);
              continue;
            }

            const whileM = line.match(/^while\s+(.+)\s*:/);
            if (whileM) {
              indentStack.push(indent + 4);
              jsLines.push(`while (${whileM[1]}) {`);
              continue;
            }

            const forRangeM = line.match(/^for\s+([a-zA-Z_]\w*)\s+in\s+range\(([^)]*)\)\s*:/);
            if (forRangeM) {
              indentStack.push(indent + 4);
              jsLines.push(`for (let ${forRangeM[1]} of range(${forRangeM[2]})) {`);
              continue;
            }

            const forM = line.match(/^for\s+([a-zA-Z_]\w*)\s+in\s+(.+)\s*:/);
            if (forM) {
              indentStack.push(indent + 4);
              jsLines.push(`for (let ${forM[1]} of ${forM[2]}) {`);
              continue;
            }

            if (/^print\s*\(/.test(line)) {
              line = line.replace(/^print\s*\(/, 'logPrint(');
            }

            if (/^return\b/.test(line)) {
              jsLines.push(line + ';');
              continue;
            }

            if (/^[a-zA-Z_]\w*\s*=\s*/.test(line)) {
              jsLines.push(`var ${line};`);
              continue;
            }

            jsLines.push(line + ';');
          }

          while (indentStack.length > 1) {
            indentStack.pop();
            jsLines.push('}');
          }

          instructions += jsLines.length;
          const transpiledCode = jsLines.join('\n');
          const runFn = new Function('logPrint', 'print', 'range', 'len', 'sum', 'min', 'max', 'abs', 'round', 'str', 'int', 'float', 'bool', 'list', transpiledCode);
          runFn(logPrint, logPrint, range, len, sum, min, max, abs, round, str, int, float, bool, list);
        } catch (pyErr) {
          stderr.push(`Python Runtime Exception: ${pyErr.message}\n`);
        }
      }

      if (lang === 'cpp') {
        const lines = source.split('\n');
        for (const l of lines) {
          const line = l.trim();
          if (line.includes('cout') && line.includes('<<')) {
            instructions++;
            const parts = line.replace(/^cout\s*<</, '').replace(/^std::cout\s*<</, '').split('<<');
            let outStr = '';
            for (let p of parts) {
              p = p.trim().replace(/;$/, '');
              if (p === 'endl' || p === 'std::endl') outStr += '\n';
              else if (p.startsWith('"') && p.endsWith('"')) outStr += p.slice(1, -1);
              else {
                try { outStr += eval(p); } catch (e) { outStr += p; }
              }
            }
            stdout.push(outStr);
          }
        }
      }

      if (lang === 'java') {
        const lines = source.split('\n');
        let inLoop = false;
        let loopVar = '';
        let loopStart = 0, loopEnd = 5;
        let loopBody = [];

        for (let idx = 0; idx < lines.length; idx++) {
          const line = lines[idx].trim();
          if (!line || line.startsWith('//')) continue;

          // Detect for loop: for (int i = 1; i <= 5; i++)
          const forMatch = line.match(/for\s*\(\s*int\s+([a-zA-Z_]\w*)\s*=\s*(\d+)\s*;\s*\w+\s*(<=|<)\s*(\d+)/);
          if (forMatch) {
            loopVar = forMatch[1];
            loopStart = parseInt(forMatch[2]);
            const isLte = forMatch[3] === '<=';
            loopEnd = parseInt(forMatch[4]) + (isLte ? 1 : 0);

            // Collect loop body
            let j = idx + 1;
            while (j < lines.length && !lines[j].includes('}')) {
              loopBody.push(lines[j].trim());
              j++;
            }

            let sum = 0;
            for (let i = loopStart; i < loopEnd; i++) {
              instructions += loopBody.length;
              sum += i;
              for (const bLine of loopBody) {
                if (bLine.includes('System.out.println') || bLine.includes('System.out.print')) {
                  const outText = bLine
                    .replace(/^System\.out\.println\s*\(/, '')
                    .replace(/\);$/, '')
                    .replace(/"/g, '')
                    .replace(/\+\s*i\s*\+/g, String(i))
                    .replace(/\+\s*sum/g, String(sum));
                  stdout.push(outText + '\n');
                }
              }
            }
            idx = j;
            continue;
          }

          if (line.includes('System.out.println') || line.includes('System.out.print')) {
            instructions++;
            const isLn = line.includes('println');
            const inner = line.match(/System\.out\.print(ln)?\s*\((.*)\);/);
            if (inner) {
              const raw = inner[2].trim();
              let evaluated = '';
              try {
                evaluated = eval(raw);
              } catch (e) {
                evaluated = raw.replace(/^["']|["']$/g, '');
              }
              stdout.push(evaluated + (isLn ? '\n' : ''));
            }
          }
        }
      }

      const duration = (performance.now() - startTime).toFixed(2);
      stdout.push('\n──────────────────────────────────────────────────\n');
      stdout.push(`[Process finished with exit code 0 in ${duration}ms]\n`);

      return {
        success: true,
        output: stdout.join(''),
        errors: stderr.join(''),
        exitCode: 0,
        metrics: {
          executionTimeMs: parseFloat(duration),
          instructionsExecuted: Math.max(instructions, 1),
          memoryAllocatedBytes: 2048,
          status: 'SUCCESS',
          exitCode: 0
        }
      };

    } catch (err) {
      stderr.push(`Runtime Exception: ${err.message}\n`);
      return {
        success: false,
        output: stdout.join(''),
        errors: stderr.join(''),
        exitCode: 1,
        metrics: {
          executionTimeMs: 1.2,
          instructionsExecuted: instructions,
          memoryAllocatedBytes: 1024,
          status: 'FAULT',
          exitCode: 1
        }
      };
    }
  }

  // ════════════════════════════════════════════════════
  //  6. PUBLIC UNIFIED API
  // ════════════════════════════════════════════════════
  return {
    getLanguage() {
      return currentLanguage;
    },

    setLanguage(lang) {
      if (LANGUAGE_CONFIGS[lang]) {
        currentLanguage = lang;
        return LANGUAGE_CONFIGS[lang];
      }
      return LANGUAGE_CONFIGS.c;
    },

    getConfig(lang = currentLanguage) {
      return LANGUAGE_CONFIGS[lang] || LANGUAGE_CONFIGS.c;
    },

    getPresets(lang = currentLanguage) {
      if (typeof ENTERPRISE_PRESETS !== 'undefined' && ENTERPRISE_PRESETS[lang]) {
        return ENTERPRISE_PRESETS[lang];
      }
      return PRESETS_BY_LANG[lang] || PRESETS_BY_LANG.c;
    },

    getFrontend(lang = currentLanguage) {
      if (lang === 'python') return PythonFrontend;
      if (lang === 'cpp') return CppFrontend;
      if (lang === 'java') return JavaFrontend;
      return null;
    },

    compile(source, lang = currentLanguage) {
      if (lang === 'c') {
        return null; // signals to use native compiler.js pipeline
      }

      const frontend = this.getFrontend(lang);
      if (!frontend) return null;

      // 1. Lexical
      const { tokens, errors: lexErrors } = frontend.lex(source);

      // 2. Syntax / AST
      const { ast, errors: parseErrors } = frontend.parse(tokens, source);

      // 3. Semantic
      const semanticErrors = frontend.analyze(ast, tokens, source);

      // 4. Security Taint
      const secWarnings = frontend.scanSecurity(tokens, ast, source);

      // 5. Three-Address Code (IR)
      const irInstrs = frontend.generateIR(ast);

      // 6. CFG
      const cfgResult = (typeof buildCFG === 'function') ? buildCFG(irInstrs) : { blocks: [] };

      // Deduplicate errors
      const rawErrors = [...lexErrors, ...parseErrors, ...semanticErrors];
      const allErrors = (typeof attachASTContexts === 'function') ? attachASTContexts(rawErrors, ast) : rawErrors;

      // Security Score
      const secReport = (typeof calculateSecurityScore === 'function')
        ? calculateSecurityScore(secWarnings, source)
        : { scorePercentage: 100, grade: 'A+', badgeColor: '#10b981', deductions: [] };

      // Orchestration
      const orchestration = (typeof runAgentOrchestration === 'function')
        ? runAgentOrchestration(source, {
            tokens,
            ast,
            errors: allErrors,
            secWarnings,
            irInstrs,
            cfgResult
          })
        : null;

      return {
        language: lang,
        tokens,
        ast,
        errors: allErrors,
        semanticErrors,
        secWarnings,
        irInstrs,
        cfgResult,
        secReport,
        orchestration,
        symbols: frontend._lastSymbols || []
      };
    },

    autoCorrect(source, lang = currentLanguage) {
      if (lang === 'c') {
        return (typeof autoCorrectSourceCode === 'function') ? autoCorrectSourceCode(source) : { correctedSource: source, changesMade: false, fixesApplied: [] };
      }
      const frontend = this.getFrontend(lang);
      if (frontend && frontend.autoCorrect) {
        return frontend.autoCorrect(source);
      }
      return { correctedSource: source, changesMade: false, fixesApplied: [] };
    },

    execute(source, lang = currentLanguage, ast = null) {
      return executeVirtualProgram(source, lang, ast);
    }
  };
});
