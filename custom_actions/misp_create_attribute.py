from typing import Annotated, Optional
import httpx
from pydantic import Field
from tracecat_registry import RegistrySecret, registry, secrets

misp_secret = RegistrySecret(
    name="misp_api",
    keys=["MISP_API_KEY"],
)

# Optionnel : déduire une catégorie par défaut si non spécifiée
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

# Liste des catégories valides selon la doc MISP
VALID_CATEGORIES = [
    "Internal reference", "Targeting data", "Antivirus detection", "Payload delivery",
    "Artifacts dropped", "Payload installation", "Persistence mechanism", "Network activity",
    "Payload type", "Attribution", "External analysis", "Financial fraud", "Support Tool",
    "Social network", "Person", "Other"
]

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
    category: Annotated[Optional[str], Field(
        None,
        description="Optional category override. Must be one of the MISP categories."
    )] = None,
    comment: Annotated[Optional[str], Field(None, description="Optional comment for the attribute")],
    verify_ssl: Annotated[bool, Field(True, description="If False, disables SSL verification (for self-signed certs).")],
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Catégorie : soit fournie manuellement, soit déduite
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

    if comment:
        attribute_payload["Attribute"]["comment"] = comment

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/attributes/add/{event_id}",
            headers=headers,
            json=attribute_payload
        )
        response.raise_for_status()
        return response.json()
