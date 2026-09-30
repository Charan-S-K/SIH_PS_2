"""
API Router for Test PCAP Suite Endpoints .
Provides endpoints to list curated scenarios, download scenario PCAP binaries, and evaluate analysis jobs against scenario ground truth.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.fixtures.test_pcap_suite import PcapSuiteScenario, generate_scenario_pcap_bytes
from app.services.pcap_suite_runner import PcapSuiteRunnerService

router = APIRouter(prefix="/pcap-suite", tags=["Test PCAP Suite"])


@router.get("/fixtures", response_model=List[PcapSuiteScenario])
def list_pcap_suite_fixtures():
    """
    Retrieves all curated regression test PCAP scenarios.
    """
    return PcapSuiteRunnerService.list_scenarios()


@router.get("/fixtures/{scenario_id}", response_model=PcapSuiteScenario)
def get_pcap_suite_fixture(scenario_id: str):
    """
    Retrieves details for a specific test PCAP scenario by ID.
    """
    scenario = PcapSuiteRunnerService.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return scenario


@router.get("/fixtures/{scenario_id}/download")
def download_pcap_suite_fixture(scenario_id: str):
    """
    Generates and downloads the raw PCAP binary file for a specified scenario.
    """
    scenario = PcapSuiteRunnerService.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")

    pcap_bytes = generate_scenario_pcap_bytes(scenario_id)
    filename = f"{scenario_id.lower()}.pcap"

    return Response(
        content=pcap_bytes,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.post("/evaluate/{job_id}", response_model=Dict[str, Any])
def evaluate_job_against_scenario(
    job_id: str,
    scenario_id: str = Query(..., description="Target PCAP scenario ID to evaluate against"),
    db: Session = Depends(get_db)
):
    """
    Evaluates an analyzed job against expected ground truth for a given test scenario.
    """
    try:
        result = PcapSuiteRunnerService.evaluate_job_against_scenario(
            db=db,
            job_id=job_id,
            scenario_id=scenario_id
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
