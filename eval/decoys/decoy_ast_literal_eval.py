"""
DECOY (SAFE): looks like code injection via eval(), but uses ast.literal_eval.

ast.literal_eval only evaluates Python literals (numbers, strings, tuples, lists,
dicts, booleans, None). It never executes function calls, attribute access, or
arbitrary expressions, so it cannot run attacker code. This is the safe way to
turn a literal string into a value. False-positive trap.
"""

import ast


def parse_amount(raw: str) -> float:
    # literal_eval, NOT eval. Only parses a literal; no code execution.
    value = ast.literal_eval(raw)
    if not isinstance(value, (int, float)):
        raise ValueError("amount must be numeric")
    return float(value)


def parse_tags(raw: str) -> list:
    value = ast.literal_eval(raw)
    if not isinstance(value, (list, tuple)):
        raise ValueError("tags must be a list")
    return list(value)
