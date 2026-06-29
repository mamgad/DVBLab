"""
DECOY (SAFE): looks like unsafe deserialization, but uses yaml.safe_load.

yaml.safe_load (and SafeLoader) cannot construct arbitrary Python objects, so the
RCE gadget chain available to yaml.load(Loader=yaml.Loader)/FullLoader-on-old-PyYAML
is not reachable. Parsing untrusted YAML this way is safe. False-positive trap.
"""

import yaml


def parse_profile(raw_yaml: str) -> dict:
    # safe_load: only builds plain dict/list/scalar types. NOT vulnerable.
    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
        raise ValueError("expected a mapping")
    return data


def load_settings(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        # Explicit SafeLoader; equivalent to safe_load.
        return yaml.load(fh, Loader=yaml.SafeLoader)
