"""
INTENTIONALLY VULNERABLE SECURITY TEST CANARY

This file exists only to demonstrate Semgrep detection.
It must never be imported, executed, or deployed.
"""

import subprocess


def unsafe_expression(user_input: str):
    """
    Intentionally unsafe: eval can interpret input as Python code.
    This function is never called.
    """
    return eval(user_input)


def unsafe_command(user_input: str) -> None:
    """
    Intentionally unsafe: shell=True with untrusted input can cause
    command injection. This function is never called.
    """
    subprocess.run(
        "echo " + user_input,
        shell=True,
        check=False,
    )
