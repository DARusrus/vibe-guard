from __future__ import annotations

import json

from typer.testing import CliRunner

from vibeguard.cli import app

runner = CliRunner()


class TestScanCommand:
    def test_scan_exits_zero_on_no_findings(self, tmp_path) -> None:
        """Clean directory with no Python files must exit 0."""
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_exits_one_on_findings(self) -> None:
        """Scanning vulnerable_app must exit 1 (findings present)."""
        result = runner.invoke(
            app, ["scan", "tests/fixtures/vulnerable_app", "--format", "terminal"]
        )
        assert result.exit_code == 1

    def test_scan_no_fail_flag_overrides_exit_code(self) -> None:
        """--no-fail must produce exit 0 even with findings."""
        result = runner.invoke(app, ["scan", "tests/fixtures/vulnerable_app", "--no-fail"])
        assert result.exit_code == 0

    def test_scan_sarif_format_produces_valid_json(self, tmp_path) -> None:
        """--format sarif --output FILE must write parseable JSON."""
        out = tmp_path / "results.sarif"
        runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable_app",
                "--format",
                "sarif",
                "--output",
                str(out),
                "--no-fail",
            ],
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert "runs" in data

    def test_scan_json_format_produces_valid_json(self, tmp_path) -> None:
        """--format json --output FILE must write parseable JSON."""
        out = tmp_path / "results.json"
        runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable_app",
                "--format",
                "json",
                "--output",
                str(out),
                "--no-fail",
            ],
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "findings" in data
        assert "summary" in data

    def test_scan_severity_filter_respected(self, tmp_path) -> None:
        """--severity CRITICAL must not include MEDIUM findings in output."""
        out = tmp_path / "results.json"
        runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable_app",
                "--severity",
                "CRITICAL",
                "--format",
                "json",
                "--output",
                str(out),
                "--no-fail",
            ],
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        for finding in data["findings"]:
            assert finding["severity"] in {"CRITICAL"}

    def test_scan_nonexistent_path_shows_error(self) -> None:
        """Nonexistent path must show error message, not traceback."""
        result = runner.invoke(app, ["scan", "/does/not/exist"])
        assert result.exit_code != 0

    def test_version_flag(self) -> None:
        """--version must print the version string and exit 0."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "vibe-guard" in result.output


class TestRulesCommand:
    def test_rules_list_prints_table(self) -> None:
        """rules command must produce output containing rule IDs."""
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "vibeguard" in result.output

    def test_rules_list_language_filter(self) -> None:
        """--language python must only show python rules."""
        result = runner.invoke(app, ["rules", "--language", "python"])
        assert result.exit_code == 0

    def test_rules_list_severity_filter(self) -> None:
        """--severity CRITICAL must only show CRITICAL rules."""
        result = runner.invoke(app, ["rules", "--severity", "CRITICAL"])
        assert result.exit_code == 0


class TestInitCommand:
    def test_init_creates_config_file(self, tmp_path) -> None:
        """init in empty dir must create .vibeguard.toml."""
        result = runner.invoke(
            app,
            ["init", str(tmp_path)],
            input="MEDIUM\n0.6\ny\nn\nn\n",
        )
        assert result.exit_code == 0
        assert (tmp_path / ".vibeguard.toml").exists()

    def test_init_aborts_on_existing_config_when_declined(self, tmp_path) -> None:
        """init must not overwrite existing config if user declines."""
        existing = tmp_path / ".vibeguard.toml"
        existing.write_text("[vibe-guard]\n", encoding="utf-8")
        result = runner.invoke(
            app,
            ["init", str(tmp_path)],
            input="n\n",
        )
        assert result.exit_code == 0
        assert existing.read_text(encoding="utf-8") == "[vibe-guard]\n"
