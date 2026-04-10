from __future__ import annotations

import ast
import re


class CommentsSignal:
    """Signal 1 — detects AI docstring and comment patterns via regex."""

    _GOOGLE_STYLE_RE = re.compile(
        r"^\s+(Args:|Returns:|Raises:)\s*$",
        flags=re.MULTILINE,
    )
    _NUMPY_STYLE_RE = re.compile(
        r"^\s+Parameters\s*\n\s*-{4,}\s*$",
        flags=re.MULTILINE,
    )
    _TODO_FEATURE_RE = re.compile(
        r"#\s*TODO[:\s].*(implement|add|create|support|handle|integrate|build|extend|allow|enable)",
        flags=re.IGNORECASE,
    )
    _WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

    def score(self, source_code: str) -> float:
        """Return confidence score 0.0–1.0 based on comment patterns."""
        if not source_code.strip():
            return 0.0

        total = 0.0
        total += self._score_google_docstring(source_code)
        total += self._score_numpy_docstring(source_code)
        total += self._score_restatement_comments(source_code)
        total += self._score_todo_feature_comments(source_code)
        total += self._score_disproportionate_docstrings(source_code)
        total += self._score_comment_density(source_code)
        return min(1.0, max(0.0, total))

    def _score_google_docstring(self, source_code: str) -> float:
        return 0.25 if self._GOOGLE_STYLE_RE.search(source_code) else 0.0

    def _score_numpy_docstring(self, source_code: str) -> float:
        return 0.20 if self._NUMPY_STYLE_RE.search(source_code) else 0.0

    def _score_restatement_comments(self, source_code: str) -> float:
        lines = source_code.splitlines()
        hits = 0

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue

            comment_text = stripped.lstrip("#").strip()
            comment_tokens = self._tokenize(comment_text)
            if len(comment_text.split()) < 6:
                continue

            nearby_code_lines: list[str] = []
            for j in range(max(0, idx - 3), min(len(lines), idx + 4)):
                if j == idx:
                    continue
                candidate = lines[j].strip()
                if candidate and not candidate.startswith("#"):
                    nearby_code_lines.append(candidate)
                if len(nearby_code_lines) == 3:
                    break

            if not nearby_code_lines:
                continue

            code_tokens = set()
            for code_line in nearby_code_lines:
                code_tokens |= self._tokenize(code_line)

            if len(comment_tokens & code_tokens) >= 3:
                hits += 1

        return min(hits * 0.05, 0.15)

    def _score_todo_feature_comments(self, source_code: str) -> float:
        return 0.20 if self._TODO_FEATURE_RE.search(source_code) else 0.0

    def _score_disproportionate_docstrings(self, source_code: str) -> float:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return 0.0

        hits = 0
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            doc = ast.get_docstring(node, clean=False)
            if not doc:
                continue

            doc_line_count = len([line for line in doc.splitlines() if line.strip()])
            if doc_line_count <= 12:
                continue

            body_start = node.body[0].lineno if node.body else node.lineno
            body_end = (
                node.body[-1].end_lineno or node.body[-1].lineno if node.body else node.lineno
            )
            body_line_count = max(0, body_end - body_start + 1)

            if body_line_count < 20:
                hits += 1

        return min(hits * 0.08, 0.15)

    def _score_comment_density(self, source_code: str) -> float:
        lines = source_code.splitlines()
        if not lines:
            return 0.0

        comment_lines = sum(1 for line in lines if line.strip().startswith("#"))
        density = comment_lines / len(lines)
        return 0.10 if density > 0.33 else 0.0

    def _tokenize(self, text: str) -> set[str]:
        return {token.lower() for token in self._WORD_RE.findall(text)}
