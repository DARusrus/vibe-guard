from __future__ import annotations

import ast
import statistics


class StructureSignal:
    """Signal 2 — AST-based structural regularity detection."""

    _TEXTBOOK_NAMES = {
        "user_id",
        "user_name",
        "username",
        "is_valid",
        "is_active",
        "response",
        "response_data",
        "result",
        "data",
        "payload",
        "token",
        "config",
        "settings",
        "handler",
        "manager",
        "service",
        "repository",
        "client",
        "session",
        "context",
        "logger",
        "db",
        "conn",
        "cursor",
        "error",
        "err",
        "success",
        "status",
        "message",
        "output",
        "value",
    }

    def score(self, source_code: str) -> float:
        """Return confidence score 0.0–1.0. Return 0.0 on parse failure."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return 0.0

        total = 0.0
        total += self._score_function_length_regularity(tree)
        total += self._score_textbook_variable_names(tree)
        total += self._score_uniform_method_count(tree)
        total += self._score_documented_public_functions(tree)
        return min(1.0, max(0.0, total))

    def _score_function_length_regularity(self, tree: ast.AST) -> float:
        lengths: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.body:
                continue
            line_count = (node.end_lineno or node.lineno) - node.lineno + 1
            if line_count > 3:
                lengths.append(line_count)

        if len(lengths) < 3:
            return 0.0

        mean_len = statistics.fmean(lengths)
        if mean_len == 0:
            return 0.0
        std_len = statistics.pstdev(lengths)
        cv = std_len / mean_len

        if cv < 0.30:
            return 0.30
        if cv < 0.60:
            return 0.15
        return 0.0

    def _score_textbook_variable_names(self, tree: ast.AST) -> float:
        matches = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    matches += self._count_textbook_targets(target)
            elif isinstance(node, ast.AnnAssign):
                matches += self._count_textbook_targets(node.target)

        return min(matches / 5, 1.0) * 0.25

    def _score_uniform_method_count(self, tree: ast.AST) -> float:
        class_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        if len(class_nodes) <= 1:
            return 0.0

        method_counts = [
            sum(1 for stmt in class_node.body if isinstance(stmt, ast.FunctionDef))
            for class_node in class_nodes
        ]

        if not method_counts:
            return 0.0
        if max(method_counts) - min(method_counts) <= 1:
            return 0.25
        return 0.0

    def _score_documented_public_functions(self, tree: ast.AST) -> float:
        public_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            line_count = (node.end_lineno or node.lineno) - node.lineno + 1
            if line_count > 5:
                public_funcs.append(node)

        if len(public_funcs) < 2:
            return 0.0

        documented = sum(1 for func in public_funcs if ast.get_docstring(func) is not None)
        if documented / len(public_funcs) >= 0.80:
            return 0.20
        return 0.0

    def _count_textbook_targets(self, target: ast.expr) -> int:
        if isinstance(target, ast.Name):
            return 1 if target.id in self._TEXTBOOK_NAMES else 0
        if isinstance(target, (ast.Tuple, ast.List)):
            return sum(self._count_textbook_targets(elt) for elt in target.elts)
        return 0
