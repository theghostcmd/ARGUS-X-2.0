
import re

# These rules detect selected common patterns.
# Tune them against legitimate application traffic before deployment.

WAF_RULES = (
    (
        "SQLI_UNION_SELECT",
        re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I),
    ),
    (
        "SQLI_BOOLEAN",
        re.compile(
            r"""(?:'|")\s*or\s+(?:'|")?\w+(?:'|")?\s*=\s*(?:'|")?\w+""",
            re.I,
        ),
    ),
    (
        "XSS_SCRIPT",
        re.compile(r"<\s*script\b|javascript\s*:", re.I),
    ),
    (
        "XSS_EVENT_HANDLER",
        re.compile(
            r"\bon(?:error|load|click)\s*=",
            re.I,
        ),
    ),
    (
        "PATH_TRAVERSAL",
        re.compile(r"\.\./|%2e%2e(?:%2f|/|%5c)", re.I),
    ),
    (
        "SHELL_METACHARACTER",
        re.compile(r"(?:\$\(|`[^`]+`)", re.I),
    ),
)
