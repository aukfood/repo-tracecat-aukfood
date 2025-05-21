"""MISP IOC Finder."""

from typing import Annotated

import httpx
from pydantic import Field

from tracecat_registry import RegistrySecret, registry, secrets

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)
"""MISP API credentials.

- name: `misp_api`
- keys:
    - `MISP_API_KEY`
"""


@registry.register(
    default_title="Search IOC in MISP",
    description="Query MISP for a given IOC (IP, domain, hash, etc.) and check if it matches any known attributes.",
    display_group="MISP",
    doc_url="https://www.circl.lu/doc/misp/automation/#searching-events",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def search_ioc_in_misp(
    misp_url: Annotated[str, Field(..., description="Base URL for the MISP instance (e.g., https://misp.local)")] ,
    ioc_value: Annotated[str, Field(..., description="The IOC value to search for (e.g., IP, domain, hash).")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (useful for internal MISP).")],
) -> dict:
    """Search a single IOC in MISP and return matching attributes, if any."""
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {
        "value": ioc_value,
        "returnFormat": "json"
    }

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{misp_url.rstrip('/')}/attributes/restSearch",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json()
