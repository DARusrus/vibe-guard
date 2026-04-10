from __future__ import annotations

import ast
import io
import re
import tokenize


class TokenSignal:
    """Signal 3 — detects AI-specific coding idioms via AST + regex."""

    _BARE_EXCEPTION_RE = re.compile(
        r"except\s+Exception\s+as\s+\w+:\s*\n\s*(pass|\.\.\.)",
        flags=re.MULTILINE,
    )
    _WILDCARD_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\*\s*$", re.MULTILINE)
    _EXPLICIT_IMPORT_RE = re.compile(
        r"^\s*from\s+([\w.]+)\s+import\s+([\w,\s]+)\s*$",
        re.MULTILINE,
    )

    def score(self, source_code: str) -> float:
        """Return confidence score 0.0–1.0."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return 0.0

        total = 0.0
        total += self._score_bare_exception_swallow(source_code)
        total += self._score_create_then_return(tree)
        total += self._score_isinstance_guards(tree)
        total += self._score_wildcard_then_explicit_import(source_code)
        total += self._score_exclusive_dict_get_usage(tree)
        total += self._score_full_annotation_coverage(tree)
        return min(1.0, max(0.0, total))

    def _score_bare_exception_swallow(self, source_code: str) -> float:
        stripped = self._strip_string_literals(source_code)
        return 0.25 if self._BARE_EXCEPTION_RE.search(stripped) else 0.0

    def _score_create_then_return(self, tree: ast.AST) -> float:
        hits = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if len(node.body) < 2:
                continue

            assign_stmt = node.body[-2]
            return_stmt = node.body[-1]
            if not isinstance(assign_stmt, ast.Assign) or len(assign_stmt.targets) != 1:
                continue
            if not isinstance(assign_stmt.targets[0], ast.Name):
                continue
            if not isinstance(return_stmt, ast.Return) or not isinstance(return_stmt.value, ast.Name):
                continue

            var_name = assign_stmt.targets[0].id
            if return_stmt.value.id != var_name:
                continue

            reused_elsewhere = any(
                isinstance(inner, ast.Name) and inner.id == var_name
                for stmt in node.body[:-2]
                for inner in ast.walk(stmt)
            )
            if not reused_elsewhere:
                hits += 1

        return min(hits * 0.15, 0.20)

    def _score_isinstance_guards(self, tree: ast.AST) -> float:
        hits = 0

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            params = [arg.arg for arg in node.args.args if arg.arg not in {"self", "cls"}]
            if len(params) < 2:
                continue

            body_half = node.body[: max(1, (len(node.body) + 1) // 2)]
            guarded_params: set[str] = set()

            for stmt in body_half:
                for call in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
                    if not isinstance(call.func, ast.Name) or call.func.id != "isinstance":
                        continue
                    if not call.args:
                        continue
                    first_arg = call.args[0]
                    if isinstance(first_arg, ast.Name) and first_arg.id in params:
                        guarded_params.add(first_arg.id)

            if guarded_params and len(guarded_params) / len(params) >= 0.5:
                hits += 1

        return min(hits * 0.15, 0.20)

    def _score_wildcard_then_explicit_import(self, source_code: str) -> float:
        wildcard_modules = {match.group(1) for match in self._WILDCARD_IMPORT_RE.finditer(source_code)}
        explicit_modules = {
            match.group(1)
            for match in self._EXPLICIT_IMPORT_RE.finditer(source_code)
            if "*" not in match.group(2)
        }
        return 0.15 if wildcard_modules & explicit_modules else 0.0

    def _score_exclusive_dict_get_usage(self, tree: ast.AST) -> float:
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            get_counts: dict[str, int] = {}
            subscript_bases: set[str] = set()

            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "get"
                    and isinstance(inner.func.value, ast.Name)
                ):
                    base_name = inner.func.value.id
                    get_counts[base_name] = get_counts.get(base_name, 0) + 1

                if isinstance(inner, ast.Subscript) and isinstance(inner.value, ast.Name):
                    subscript_bases.add(inner.value.id)

            for base_name, count in get_counts.items():
                if count >= 3 and base_name not in subscript_bases:
                    return 0.10

        return 0.0

    def _score_full_annotation_coverage(self, tree: ast.AST) -> float:
        hits = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            params = [arg for arg in node.args.args if arg.arg not in {"self", "cls"}]
            if len(params) < 2:
                continue

            if not all(param.annotation is not None for param in params):
                continue

            assign_nodes = [n for n in ast.walk(node) if isinstance(n, (ast.Assign, ast.AnnAssign))]
            if not assign_nodes:
                continue

            ann_assign_nodes = [n for n in assign_nodes if isinstance(n, ast.AnnAssign)]
            if len(ann_assign_nodes) / len(assign_nodes) > 0.60:
                hits += 1

        return min(hits * 0.05, 0.10)

    def _strip_string_literals(self, source_code: str) -> str:
        """Replace string literals to avoid regex false positives inside strings."""
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source_code).readline))
            cleaned: list[tokenize.TokenInfo] = []
            for tok in tokens:
                if tok.type == tokenize.STRING:
                    cleaned.append(tokenize.TokenInfo(tok.type, "''", tok.start, tok.end, tok.line))
                else:
                    cleaned.append(tok)
            return tokenize.untokenize(cleaned)
        except (tokenize.TokenError, IndentationError):
            return source_code
