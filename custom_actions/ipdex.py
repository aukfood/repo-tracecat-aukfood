import subprocess
import json
from typing import Annotated
from pydantic import Field
from tracecat_registry import registry

@registry.register(
    default_title="Ipdex Query",
    description="Run ipdex CLI for IP or file input, get JSON output and return data.",
    display_group="Tools.Ipdex",
    namespace="tools.ipdex",
)
def ipdex_query(
    input_arg: Annotated[str, Field(..., description="IP address or path to file to analyze")],
    detailed: Annotated[bool, Field(False, description="Show detailed info with -d flag")],
    yes: Annotated[bool, Field(False, description="Auto say yes to warnings with -y flag")],
) -> dict:
    # Construire la commande ipdex
    cmd = ['ipdex', input_arg, '-o', 'json']
    if detailed:
        cmd.append('-d')
    if yes:
        cmd.append('-y')

    # Exécuter la commande et capturer la sortie
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # Parse la sortie JSON
    data = json.loads(result.stdout)

    return data
