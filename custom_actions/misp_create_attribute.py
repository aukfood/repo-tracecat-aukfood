from typing import Annotated, Optional, List
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

VALID_CATEGORIES = [
    "Internal reference", "Targeting data", "Antivirus detection", "Payload delivery",
    "Artifacts dropped", "Payload installation", "Persistence mechanism", "Network activity",
    "Payload type", "Attribution", "External analysis", "Financial fraud", "Support Tool",
    "Social network", "Person", "Other"
]

def get_category_for_ioc_type(ioc_type: str) -> str:
    mapping = {
        "ip-src": "Network activity",
        "ip-dst": "Network activity",
        "domain": "Network activity",
        "hostname": "Network activity",
        "url": "Network activity",
        "sha256": "Payload delivery",
        "sha1": "Payload delivery",
        "md5": "Payload delivery",
        "filename": "Artifacts dropped",
        "email-src": "Payload delivery",
        "email-dst": "Payload delivery",
        "mutex": "Persistence mechanism",
        "regkey": "Persistence mechanism",
    }
    return mapping.get(ioc_type.lower(), "Network activity")

@registry.register(
    default_title="Add Attribute to MISP Event",
    description="Adds a custom attribute to an existing MISP event. Supports manual or inferred category.",
    display_group="MISP",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def add_attribute_to_misp_event(
    base_url: Annotated[str, Field(..., description="Base URL of the MISP instance (e.g., https://misp.local)")],
    event_id: Annotated[int, Field(..., description="ID of the MISP event to add the attribute to")],
    ioc_value: Annotated[str, Field(..., description="The IOC value to add (e.g., IP, domain, hash, etc.)")],
    ioc_type: Annotated[str, Field(..., description="MISP-compatible IOC type (e.g., ip-src, domain, sha256, etc.)")],
    to_ids: Annotated[bool, Field(True, description="Should this attribute be used for IDS signatures?")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification.")] = True,
    category: Annotated[Optional[str], Field(None, description="Optional category override")] = None,
    comment: Annotated[Optional[str], Field(None, description="Optional comment")] = None,
    event_info: Annotated[Optional[str], Field(None, description="Optional event info/title")] = None,
    tags: Annotated[Optional[List[str]], Field(None, description="Optional tags to attach to the attribute")] = None,
    threat_level_id: Annotated[Optional[int], Field(None, description="Optional threat level ID")] = None,
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    selected_category = category or get_category_for_ioc_type(ioc_type)

    if category and category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category '{category}'. Must be one of: {', '.join(VALID_CATEGORIES)}")

    attribute_payload = {
        "Attribute": {
            "type": ioc_type,
            "value": ioc_value,
            "category": selected_category,
            "to_ids": to_ids,
        }
    }

    if comment and comment.strip():
        attribute_payload["Attribute"]["comment"] = comment.strip()

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/attributes/add/{event_id}",
            headers=headers,
            json=attribute_payload
        )
        response.raise_for_status()
        result = response.json()

        if tags:
            for tag in tags:
                tag_payload = {"Tag": {"name": tag}}
                await client.post(
                    f"{base_url.rstrip('/')}/events/addTag/{event_id}",
                    headers=headers,
                    json=tag_payload
                )

        if event_info or threat_level_id:
            edit_event_payload = {"Event": {}}
            if event_info:
                edit_event_payload["Event"]["info"] = event_info
            if threat_level_id is not None:
                edit_event_payload["Event"]["threat_level_id"] = threat_level_id

            await client.post(
                f"{base_url.rstrip('/')}/events/edit/{event_id}",
                headers=headers,
                json=edit_event_payload
            )

        return result
