from typing import Annotated, List
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

@registry.register(
    default_title="Enrich MISP Event",
    description="Enrich an existing MISP event using selected enrichment modules.",
    display_group="MISP",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def enrich_misp_event(
    base_url: Annotated[str, Field(..., description="Base URL of the MISP instance (e.g., https://misp.local)")],
    event_id: Annotated[int, Field(..., description="ID of the MISP event to enrich")],
    modules: Annotated[List[str], Field(..., description="List of enrichment module names to apply")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (for self-signed certs).")],
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {
        "event_id": str(event_id),
        "modules": modules
    }

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/events/enrichEvent",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()
