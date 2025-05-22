from typing import Annotated, List, Optional
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets
from datetime import datetime

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

def get_category_for_ioc_type(ioc_type: str) -> str:
    mapping = {
        "ip-src": "Network activity",
        "ip-dst": "Network activity",
        "domain": "Network activity",
        "url": "Network activity",
        "sha256": "Payload delivery",
        "md5": "Payload delivery",
        "email-src": "Payload delivery",
        "filename": "Artifacts dropped",
    }
    return mapping.get(ioc_type.lower(), "Network activity")

@registry.register(
    default_title="Create MISP Event from IOC",
    description="Ingests a generic alert into MISP by creating an event and adding an IOC as attribute.",
    display_group="MISP",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def create_misp_event_from_ioc(
    base_url: Annotated[str, Field(..., description="Base URL of the MISP instance (e.g., https://misp.local)")],
    ioc_value: Annotated[str, Field(..., description="The IOC value to register in MISP (IP, domain, hash, etc.)")],
    ioc_type: Annotated[str, Field(..., description="MISP-compatible IOC type (e.g., ip-src, domain, sha256, etc.)")],
    event_info: Annotated[str, Field(..., description="Short description of the alert, e.g., 'Suspicious login from X'.")],
    threat_level_id: Annotated[int, Field(3, description="1=High, 2=Medium, 3=Low, 4=Undefined")],
    distribution: Annotated[int, Field(0, description="0=Your org, 1=Community only, 2=Connected communities, 3=All")],
    to_ids: Annotated[bool, Field(True, description="Should this attribute be used for IDS signatures?")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (for self-signed certs).")],
    tags: Annotated[Optional[List[str]], Field(None, description="Optional list of tags to add to the event")]=None,
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    category = get_category_for_ioc_type(ioc_type)

    event_payload = {
        "Event": {
            "info": event_info,
            "analysis": "2",
            "threat_level_id": str(threat_level_id),
            "distribution": str(distribution),
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
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

    # Ajouter les tags si fournis
    if tags:
        event_payload["Event"]["Tag"] = [{"name": tag} for tag in tags]

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/events",
            headers=headers,
            json=event_payload,
        )
        response.raise_for_status()
        return response.json()
