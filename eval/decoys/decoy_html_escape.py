"""
DECOY (SAFE): looks like reflected XSS, but user input is HTML-escaped before
it ever reaches the response, and Jinja autoescaping is left enabled.

markupsafe.escape() converts <, >, &, ", ' to entities, so attacker-controlled
text cannot break out of the HTML/attribute context. render_template_string is
used with a CONSTANT template and the value passed as an autoescaped variable,
not concatenated into the template source. False-positive trap.
"""

from markupsafe import escape
from jinja2 import Environment, select_autoescape


def render_greeting(username: str) -> str:
    # escape() neutralizes HTML metacharacters before interpolation.
    safe_name = escape(username)
    return f"<p>Hello, {safe_name}!</p>"


def render_profile(display_name: str) -> str:
    # Autoescaping ON; the template is a constant and the value is a bound
    # variable, so Jinja escapes it. No SSTI (template is not user-controlled).
    env = Environment(autoescape=select_autoescape(default=True))
    template = env.from_string("<div class='profile'>{{ name }}</div>")
    return template.render(name=display_name)
