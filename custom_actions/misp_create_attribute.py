from typing import Annotated, Optional
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

@registry.register(
    default_title="Add MISP Attribute",
    description="Add a new attribute to an existing MISP event.",
    display_group="MISP",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def add_misp_attribute(
    base_url: Annotated[str, Field(..., description="Base URL of the MISP instance (e.g., https://misp.local)")],
    event_id: Annotated[int, Field(..., description="ID of the MISP event to add the attribute to")],
    type: Annotated[str, Field(..., description="Type of the attribute (e.g., 'ip-src', 'domain', 'hash')")],
    value: Annotated[str, Field(..., description="Value of the attribute")],
    category: Annotated[str, Field("External analysis", description="Category of the attribute (e.g., 'Network activity', 'Payload delivery')")],
    to_ids: Annotated[bool, Field(True, description="Whether the attribute is intended for IDS detection")],
    comment: Annotated[Optional[str], Field(None, description="Optional comment for the attribute")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (for self-signed certs).")],
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {
        "Attribute": {
            "type": type,
            "value": value,
            "category": category,
            "to_ids": to_ids,
        }
    }

    if comment:
        payload["Attribute"]["comment"] = comment

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/attributes/add/{event_id}",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
