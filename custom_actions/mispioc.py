"""MISP IOC Submission Node."""

from typing import Annotated
from pydantic import Field
from tracecat_registry import registry, RegistrySecret
from pymisp import ExpandedPyMISP, MISPEvent
import iocextract

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
    default_title="Push IOCs to MISP",
    description="Extract IOCs from input text and create a MISP event.",
    display_group="MISP",
    doc_url="https://www.misp-project.org/documentation/",
    namespace="tools.misp",
    secrets=[misp_secret],
)
async def push_iocs_to_misp(
    url: Annotated[str, Field(..., description="Base URL of your MISP instance (e.g. https://misp.local).")],
    verify_ssl: Annotated[
        bool,
        Field(
            True,
            description="Disable SSL verification if using internal CA.",
        ),
    ],
    event_info: Annotated[str, Field(..., description="Title/info of the MISP event.")],
    distribution: Annotated[int, Field(0, description="Distribution level (0=org, 1=community, etc).")],
    threat_level_id: Annotated[int, Field(2, description="Threat level ID (1=high, 2=medium, 3=low, 4=undefined).")],
    analysis: Annotated[int, Field(1, description="Analysis level (0=initial, 1=ongoing, 2=completed).")],
    log: Annotated[str, Field(..., description="Raw log or report text to extract IOCs from.")],
) -> dict:
    """Extracts IOCs from a log string and creates a new MISP event with them."""

    # Get API key from secret
    from tracecat_registry import secrets
    api_key = secrets.get("MISP_API_KEY", secret_name="misp_api")

    try:
        # Initialize MISP
        misp = ExpandedPyMISP(url, api_key, verify_ssl)

        # Extract IOCs
        iocs_found = {
            'ip-dst': set(iocextract.extract_ips(log)),
            'domain': set(iocextract.extract_domains(log)),
            'url': set(iocextract.extract_urls(log)),
            'md5': set(iocextract.extract_hashes(log, hash_type="md5")),
            'sha1': set(iocextract.extract_hashes(log, hash_type="sha1")),
            'sha256': set(iocextract.extract_hashes(log, hash_type="sha256")),
        }

        total_iocs = sum(len(v) for v in iocs_found.values())
        if total_iocs == 0:
            return {"status": "ok", "message": "No IOCs found in input.", "ioc_count": 0}

        # Create MISP Event
        event = MISPEvent()
        event.info = event_info
        event.distribution = distribution
        event.analysis = analysis
        event.threat_level_id = threat_level_id

        for attr_type, values in iocs_found.items():
            for value in values:
                event.add_attribute(type=attr_type, value=value)

        # Push to MISP
        result = misp.add_event(event)
        event_id = result.get("Event", {}).get("id", "N/A")

        return {
            "status": "ok",
            "message": f"{total_iocs} IOCs sent to MISP.",
            "ioc_count": total_iocs,
            "misp_event_id": event_id
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
