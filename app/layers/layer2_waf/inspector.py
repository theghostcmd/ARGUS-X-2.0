
from urllib.parse import unquote

from app.layers.layer2_waf.rules import WAF_RULES


def inspect_text(value: str) -> str | None:
    """
    Inspect text for selected suspicious patterns.
    Returns a rule name if matched, otherwise None.
    """
    if not value:
        return None

    decoded = unquote(value)

    for rule_name, pattern in WAF_RULES:
        if pattern.search(decoded):
            return rule_name

    return None
