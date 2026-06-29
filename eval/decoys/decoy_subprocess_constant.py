"""
DECOY (SAFE): looks like command injection, but there is no user input and no shell.

subprocess.run/check_output here use a fixed argument LIST (not a string) with the
default shell=False, and every argument is a hardcoded constant. No request data
reaches the command line, so there is nothing to inject. False-positive trap.
"""

import subprocess


def disk_usage_report() -> str:
    # Constant argv list, shell=False (default). No user input anywhere.
    result = subprocess.run(
        ["df", "-h", "/"],
        capture_output=True,
        text=True,
        shell=False,
        check=True,
    )
    return result.stdout


def kernel_version() -> str:
    # check_output with a constant list; still no shell, no interpolation.
    return subprocess.check_output(["uname", "-r"], text=True)


def list_app_processes() -> str:
    return subprocess.run(
        ["ps", "-eo", "pid,comm"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
