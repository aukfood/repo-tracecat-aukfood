from typing import Annotated, Optional
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets
from datetime import datetime

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

@registry.register(
    default_title="Create MISP Event from IOC",
    description="Ingests a generic alert into MISP by creating an event and adding an IOC as attribute.",
    display_group="MISP",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def create_misp_event_from_ioc(
    misp_url: Annotated[str, Field(..., description="Base URL of the MISP instance (e.g., https://misp.local)")],
    ioc_value: Annotated[str, Field(..., description="The IOC value to register in MISP (IP, domain, hash, etc.)")],
    ioc_type: Annotated[str, Field(..., description="MISP-compatible IOC type (e.g., ip-src, domain, sha256, etc.)")],
    event_info: Annotated[str, Field(..., description="Short description of the alert, e.g., 'Suspicious login from X'.")],
    category: Annotated[str, Field("Network activity", description="Category for the IOC (e.g., Network activity, Payload delivery, etc.)")],
    threat_level_id: Annotated[int, Field(3, description="1=High, 2=Medium, 3=Low, 4=Undefined")],
    distribution: Annotated[int, Field(0, description="0=Your org, 1=Community only, 2=Connected communities, 3=All")],
    to_ids: Annotated[bool, Field(True, description="Should this attribute be used for IDS signatures?")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (for self-signed certs).")],
    date: Annotated[Optional[str], Field(None, description="Event date in YYYY-MM-DD format. If not provided, defaults to today.")]=None,
) -> dict:
    # Si date non renseignée, on prend la date du jour UTC
    if not date:
        date = datetime.utcnow().strftime("%Y-%m-%d")

    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    event_payload = {
        "Event": {
            "info": event_info,
            "analysis": "2",  # Completed
            "threat_level_id": str(threat_level_id),
            "distribution": str(distribution),
            "date": date,
            "Attribute": [
                {
                    "type": ioc_type,
                    "category": category,
                    "value": ioc_value,
                    "to_ids": to_ids
                }
            ]
        }
    }

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{misp_url.rstrip('/')}/events",
            headers=headers,
            json=event_payload,
        )
        response.raise_for_status()
        return response.json()
