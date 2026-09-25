#!/usr/bin/env python3
"""Surface nextest tests that only passed after a retry.

`retries = 2` in .config/nextest.toml buys a green build when a devnet port
binds slowly or a container starts late. It also hides the fact that a test
is unstable, because the run reports success either way. This reads the JUnit
report nextest writes and emits a GitHub warning per test that needed a
retry, so instability stays visible without failing the build.

Usage: warn_flaky.py <path-to-junit.xml>
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# nextest records each failed attempt of an eventually-passing test as one of
# these elements alongside the successful one.
RETRY_TAGS = {"flakyFailure", "flakyError"}
# A test that ended in one of these did not pass, so it is not flaky — it is
# reported by the run itself.
TERMINAL_TAGS = {"failure", "error", "skipped"}


def warning(title: str, message: str) -> None:
    """Emit a GitHub workflow warning command."""
    # Workflow commands are line-oriented; the data field has to be escaped or
    # a multi-line message silently truncates at the first newline.
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::warning title={title}::{escaped}")


def report_flakes(path: Path) -> int:
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        # A compile failure or a cancelled run produces no report. That is not
        # an error here; the run itself already failed.
        print(f"No JUnit report at {path}; skipping flaky-test warnings.")
        return 0
    except (ET.ParseError, OSError) as error:
        warning("Flaky-test report unavailable", f"Could not read {path}: {error}")
        return 0

    flaky = 0
    for case in root.iter("testcase"):
        # Only DIRECT children describe this test's outcome. Captured stdout is
        # nested inside <system-out> and can itself contain XML-like text, so
        # iterating descendants would count a test's own log output as a result.
        children = [child.tag for child in case]
        if any(tag in TERMINAL_TAGS for tag in children):
            continue
        retries = sum(tag in RETRY_TAGS for tag in children)
        if retries:
            flaky += 1
            name = f"{case.get('classname', '')}::{case.get('name', '(unnamed)')}"
            warning(
                "Flaky test",
                f"{name} passed after {retries} failed attempt(s). "
                f"Retries are masking instability here — see the nextest output.",
            )

    if flaky:
        print(f"{flaky} test(s) passed only after a retry.")
    else:
        print("No flaky tests in this run.")
    return flaky


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <junit.xml>", file=sys.stderr)
        raise SystemExit(2)
    # Always exit 0: this is a reporter, not a gate.
    report_flakes(Path(sys.argv[1]))
