"""Create a MISP event and add an IOC."""

from typing import Annotated
from pydantic import Field
import httpx

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
    default_title="Create MISP event with IOC",
    description="Create a new event in MISP, add an IOC as attribute, and publish the event.",
    display_group="MISP",
    doc_url="https://www.circl.lu/doc/misp/automation/#rest",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def create_misp_event_with_ioc(
    misp_url: Annotated[str, Field(..., description="Base URL of your MISP instance (e.g., https://misp.local)")],
    ioc_value: Annotated[str, Field(..., description="The IOC value to add (e.g., IP, hash, domain).")],
    ioc_type: Annotated[str, Field("ip-dst", description="Type of the IOC (e.g., ip-dst, domain, md5, etc.)")],
    event_info: Annotated[str, Field("IOC created via Tracecat", description="Description/title of the MISP event.")],
    distribution: Annotated[int, Field(0, description="Distribution level: 0=Your org, 1=This community, 2=Connected communities, 3=All")],
    threat_level_id: Annotated[int, Field(2, description="Threat level: 1=High, 2=Medium, 3=Low, 4=Undefined")],
    analysis: Annotated[int, Field(0, description="Analysis status: 0=Initial, 1=Ongoing, 2=Completed")],
    publish_event: Annotated[bool, Field(True, description="If True, publishes the event after creation.")],
    verify_ssl: Annotated[bool, Field(True, description="Disable only for internal MISP with self-signed certs")],
) -> dict:
    headers = {
        "Authorization": secrets.get("MISP_API_KEY"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        # Step 1: Create the event
        event_payload = {
            "Event": {
                "info": event_info,
                "distribution": distribution,
                "threat_level_id": threat_level_id,
                "analysis": analysis
            }
        }
        res_event = await client.post(
            f"{misp_url.rstrip('/')}/events",
            headers=headers,
            json=event_payload
        )
        res_event.raise_for_status()
        event_id = res_event.json()["Event"]["id"]

        # Step 2: Add the IOC as attribute
        attribute_payload = {
            "Attribute": {
                "type": ioc_type,
                "category": "Network activity",
                "value": ioc_value,
                "to_ids": True
            }
        }
        res_attr = await client.post(
            f"{misp_url.rstrip('/')}/attributes/add/{event_id}",
            headers=headers,
            json=attribute_payload
        )
        res_attr.raise_for_status()

        # Step 3: Publish the event (if selected)
        if publish_event:
            await client.post(
                f"{misp_url.rstrip('/')}/events/publish/{event_id}",
                headers=headers,
            )

        return {
            "event_id": event_id,
            "ioc_added": ioc_value,
            "type": ioc_type,
            "published": publish_event
        }
