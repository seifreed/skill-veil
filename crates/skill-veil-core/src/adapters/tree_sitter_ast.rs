//! Tree-sitter implementation of the [`ScriptAstAnalyzer`] port.
//!
//! Walks the concrete syntax tree of a referenced Python / JavaScript /
//! TypeScript script and flags structural constructs a flat regex misses:
//! dynamic evaluation, process spawning, dynamic imports, indirect access to
//! interpreter builtins, and string concatenation flowing into evaluation.
//!
//! The analyzer is `Send + Sync`: it stores only cheap clonable
//! `tree_sitter::Language` handles and builds a fresh `Parser` per call, so
//! no mutable parser state is shared across threads. Parse failures fail open
//! (empty result) per the port contract — a malformed script never aborts a
//! scan.

use crate::ports::{AstSignal, AstSignalKind, ScriptAstAnalyzer, ScriptLanguage};
use tree_sitter::{Language, Node, Parser};

/// Maximum characters of source retained in a signal's `evidence` snippet.
const EVIDENCE_MAX_CHARS: usize = 80;

/// Default AST analyzer backed by the bundled tree-sitter grammars.
#[derive(Clone)]
pub struct TreeSitterAstAnalyzer {
    python: Language,
    javascript: Language,
    typescript: Language,
}

impl Default for TreeSitterAstAnalyzer {
    fn default() -> Self {
        Self {
            python: tree_sitter_python::LANGUAGE.into(),
            javascript: tree_sitter_javascript::LANGUAGE.into(),
            typescript: tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        }
    }
}

impl TreeSitterAstAnalyzer {
    fn language_for(&self, language: ScriptLanguage) -> &Language {
        match language {
            ScriptLanguage::Python => &self.python,
            ScriptLanguage::JavaScript => &self.javascript,
            ScriptLanguage::TypeScript => &self.typescript,
        }
    }
}

impl ScriptAstAnalyzer for TreeSitterAstAnalyzer {
    fn analyze(&self, content: &str, language: ScriptLanguage) -> Vec<AstSignal> {
        let mut parser = Parser::new();
        if parser.set_language(self.language_for(language)).is_err() {
            return Vec::new();
        }
        let Some(tree) = parser.parse(content, None) else {
            return Vec::new();
        };
        let src = content.as_bytes();
        let mut out = Vec::new();
        walk(tree.root_node(), src, language, &mut out);
        out
    }
}

fn walk(node: Node, src: &[u8], language: ScriptLanguage, out: &mut Vec<AstSignal>) {
    match language {
        ScriptLanguage::Python => visit_python(node, src, out),
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => visit_js(node, src, out),
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, language, out);
    }
}

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn snippet(node: Node, src: &[u8]) -> String {
    node_text(node, src)
        .chars()
        .take(EVIDENCE_MAX_CHARS)
        .collect()
}

fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

fn first_argument<'a>(call: Node<'a>, field: &str) -> Option<Node<'a>> {
    let args = call.child_by_field_name(field)?;
    let mut cursor = args.walk();
    let mut named = args.named_children(&mut cursor);
    named.next()
}

fn push(out: &mut Vec<AstSignal>, kind: AstSignalKind, node: Node, src: &[u8]) {
    out.push(AstSignal {
        kind,
        line: line_of(node),
        evidence: snippet(node, src),
    });
}

fn visit_python(node: Node, src: &[u8], out: &mut Vec<AstSignal>) {
    if node.kind() == "subscript" {
        if let Some(value) = node.child_by_field_name("value") {
            let v = node_text(value, src);
            if v == "globals()" || v == "locals()" || v == "vars()" || v == "__builtins__" {
                push(out, AstSignalKind::IndirectBuiltinAccess, node, src);
            }
        }
        return;
    }
    if node.kind() != "call" {
        return;
    }
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let func_text = node_text(func, src);

    match func.kind() {
        "identifier" => match func_text {
            "exec" | "eval" | "compile" => {
                push(out, AstSignalKind::DynamicCodeExecution, node, src);
                if first_argument(node, "arguments").is_some_and(|a| a.kind() == "binary_operator")
                {
                    push(out, AstSignalKind::StringToCodeFlow, node, src);
                }
            }
            "__import__" => push(out, AstSignalKind::DynamicImport, node, src),
            "getattr" | "setattr"
                if first_argument(node, "arguments")
                    .is_some_and(|a| node_text(a, src) == "__builtins__") =>
            {
                push(out, AstSignalKind::IndirectBuiltinAccess, node, src);
            }
            _ => {}
        },
        "attribute" => {
            if let Some(kind) = classify_python_dotted(func_text) {
                push(out, kind, node, src);
            }
        }
        _ => {}
    }
}

fn classify_python_dotted(dotted: &str) -> Option<AstSignalKind> {
    let method = dotted.rsplit('.').next().unwrap_or(dotted);
    if dotted.starts_with("subprocess.")
        && matches!(
            method,
            "run"
                | "Popen"
                | "call"
                | "check_call"
                | "check_output"
                | "getoutput"
                | "getstatusoutput"
        )
    {
        return Some(AstSignalKind::ProcessExecution);
    }
    if dotted.starts_with("os.")
        && (matches!(method, "system" | "popen")
            || method.starts_with("exec")
            || method.starts_with("spawn"))
    {
        return Some(AstSignalKind::ProcessExecution);
    }
    if dotted == "importlib.import_module" || dotted == "importlib.__import__" {
        return Some(AstSignalKind::DynamicImport);
    }
    None
}

fn visit_js(node: Node, src: &[u8], out: &mut Vec<AstSignal>) {
    if node.kind() == "new_expression" {
        if let Some(ctor) = node.child_by_field_name("constructor") {
            if node_text(ctor, src) == "Function" {
                push(out, AstSignalKind::DynamicCodeExecution, node, src);
            }
        }
        return;
    }
    if node.kind() != "call_expression" {
        return;
    }
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };

    match func.kind() {
        "identifier" => match node_text(func, src) {
            "eval" | "Function" => push(out, AstSignalKind::DynamicCodeExecution, node, src),
            "require" if first_arg_is_dynamic(node) => {
                push(out, AstSignalKind::DynamicImport, node, src);
            }
            _ => {}
        },
        // Dynamic `import(<expr>)` parses with an `import` keyword callee.
        "import" if first_arg_is_dynamic(node) => {
            push(out, AstSignalKind::DynamicImport, node, src);
        }
        "member_expression" => {
            if let Some(kind) = classify_js_member(func, src) {
                push(out, kind, node, src);
            }
        }
        _ => {}
    }
}

/// True when a call's first argument is anything other than a plain string or
/// template literal — i.e. the target is computed rather than static.
fn first_arg_is_dynamic(call: Node) -> bool {
    match first_argument(call, "arguments") {
        Some(arg) => !matches!(arg.kind(), "string" | "template_string"),
        None => false,
    }
}

fn classify_js_member(member: Node, src: &[u8]) -> Option<AstSignalKind> {
    let property = member
        .child_by_field_name("property")
        .map(|p| node_text(p, src))
        .unwrap_or_default();
    let object = member
        .child_by_field_name("object")
        .map(|o| node_text(o, src))
        .unwrap_or_default();

    // Process-spawning methods. `.exec`/`.execSync` collide with
    // `RegExp.prototype.exec`, so require a child_process-flavoured receiver
    // for those; the remaining methods have no common benign collision.
    if matches!(
        property,
        "spawn" | "spawnSync" | "fork" | "execFile" | "execFileSync"
    ) {
        return Some(AstSignalKind::ProcessExecution);
    }
    if matches!(property, "exec" | "execSync") && object_looks_like_child_process(object) {
        return Some(AstSignalKind::ProcessExecution);
    }
    if object == "vm"
        && matches!(
            property,
            "runInContext" | "runInNewContext" | "compileFunction"
        )
    {
        return Some(AstSignalKind::DynamicCodeExecution);
    }
    None
}

fn object_looks_like_child_process(object: &str) -> bool {
    let lower = object.to_ascii_lowercase();
    lower.contains("child_process") || lower == "cp" || lower == "childprocess"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py(code: &str) -> Vec<AstSignal> {
        TreeSitterAstAnalyzer::default().analyze(code, ScriptLanguage::Python)
    }

    fn js(code: &str) -> Vec<AstSignal> {
        TreeSitterAstAnalyzer::default().analyze(code, ScriptLanguage::JavaScript)
    }

    fn has(signals: &[AstSignal], kind: AstSignalKind) -> bool {
        signals.iter().any(|s| s.kind == kind)
    }

    #[test]
    fn python_obfuscated_builtin_access_fires_where_regex_cannot() {
        // The star case: no literal eval token exists anywhere, so a regex for
        // the dynamic-eval keyword cannot match — but the AST sees the
        // getattr-on-builtins.
        let code = "getattr(__builtins__, 'ex' + 'ec')('import os')\n";
        let signals = py(code);
        assert!(
            has(&signals, AstSignalKind::IndirectBuiltinAccess),
            "indirect builtin access must fire; got {signals:?}"
        );
    }

    #[test]
    fn python_plain_eval_fires() {
        assert!(has(
            &py("eval(user_input)\n"),
            AstSignalKind::DynamicCodeExecution
        ));
    }

    #[test]
    fn python_string_concat_into_eval_flags_flow() {
        let signals = py("eval('1' + '+' + '1')\n");
        assert!(has(&signals, AstSignalKind::DynamicCodeExecution));
        assert!(has(&signals, AstSignalKind::StringToCodeFlow));
    }

    #[test]
    fn python_subprocess_run_fires_process_execution() {
        assert!(has(
            &py("import subprocess\nsubprocess.run(['ls'])\n"),
            AstSignalKind::ProcessExecution
        ));
    }

    #[test]
    fn python_os_system_fires_process_execution() {
        assert!(has(
            &py("import os\nos.system(cmd)\n"),
            AstSignalKind::ProcessExecution
        ));
    }

    #[test]
    fn python_dynamic_import_fires() {
        assert!(has(
            &py("import importlib\nimportlib.import_module(name)\n"),
            AstSignalKind::DynamicImport
        ));
        assert!(has(&py("__import__(name)\n"), AstSignalKind::DynamicImport));
    }

    #[test]
    fn python_benign_code_produces_nothing() {
        let signals =
            py("import json\nprint(json.dumps({'ok': True}))\ndef add(a, b):\n    return a + b\n");
        assert!(
            signals.is_empty(),
            "benign code must not fire; got {signals:?}"
        );
    }

    #[test]
    fn python_mentions_in_string_do_not_fire() {
        // The dangerous names appear only inside a string literal.
        let signals = py("doc = 'never call the eval builtin or subprocess.run here'\n");
        assert!(
            signals.is_empty(),
            "string mentions must not fire; got {signals:?}"
        );
    }

    #[test]
    fn js_eval_fires() {
        assert!(has(
            &js("eval(payload)\n"),
            AstSignalKind::DynamicCodeExecution
        ));
    }

    #[test]
    fn js_new_function_fires() {
        assert!(has(
            &js("const f = new Function('a', 'return a')\n"),
            AstSignalKind::DynamicCodeExecution
        ));
    }

    #[test]
    fn js_child_process_spawn_fires() {
        let code = "const cp = require('child_process'); cp.spawn('sh', ['-c', x])\n";
        assert!(has(&js(code), AstSignalKind::ProcessExecution));
    }

    #[test]
    fn js_regexp_exec_does_not_fire_process_execution() {
        // re.exec(str) is RegExp.prototype.exec — must not be flagged.
        let signals = js("const re = /a/; const m = re.exec(input)\n");
        assert!(
            !has(&signals, AstSignalKind::ProcessExecution),
            "RegExp.exec must not be process execution; got {signals:?}"
        );
    }

    #[test]
    fn js_static_require_does_not_fire() {
        assert!(!has(
            &js("const fs = require('fs')\n"),
            AstSignalKind::DynamicImport
        ));
    }

    #[test]
    fn js_dynamic_require_fires() {
        assert!(has(
            &js("const m = require(moduleName)\n"),
            AstSignalKind::DynamicImport
        ));
    }

    #[test]
    fn unparseable_input_fails_open() {
        // Nonsense the grammar cannot parse cleanly still returns a Vec, never
        // panics.
        let _ = py("def (((( :: garbage");
        let _ = js("function ((( ;;; ###");
    }
}
