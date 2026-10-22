"""
Integration tests for the NetSec Analyzer API endpoints powering the Home Dashboard.
Tests project creation, configuration ingestion, analysis triggering, and metrics calculation.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage.db import StorageManager

client = TestClient(app)

SAMPLE_ROUTER_CONFIG = """
hostname Campus-Edge-R1
enable password ciscosecret
no service password-encryption
!
interface GigabitEthernet0/0
 description Internet-WAN
 ip address 198.51.100.2 255.255.255.252
 ip access-group 101 in
 no shutdown
!
interface GigabitEthernet0/1
 description Core-Uplink
 ip address 10.0.0.1 255.255.255.252
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 198.51.100.1
!
access-list 101 permit ip any any
!
line vty 0 4
 transport input telnet
 login
"""


def test_api_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "NetSec Analyzer API"


def test_home_dashboard_workflow():
    # 1. Create a project
    create_res = client.post("/api/projects", json={
        "name": "Milestone1_Campus_Test",
        "description": "Integration test for Home Dashboard project creation"
    })
    assert create_res.status_code == 200
    proj_data = create_res.json()
    proj_id = proj_data["id"]
    assert proj_id is not None

    # 2. Ingest router config
    paste_res = client.post(f"/api/projects/{proj_id}/paste-config", json={
        "filename": "Campus-Edge-R1.cfg",
        "config_text": SAMPLE_ROUTER_CONFIG
    })
    assert paste_res.status_code == 200
    paste_data = paste_res.json()
    assert paste_data["device"]["device_hostname"] == "Campus-Edge-R1"
    assert paste_data["device"]["interfaces_count"] == 2

    # 3. Trigger analysis
    analyze_res = client.post(f"/api/projects/{proj_id}/analyze")
    assert analyze_res.status_code == 200
    run_data = analyze_res.json()
    
    # Verify core Home Dashboard metrics
    assert run_data["devices_count"] == 1
    assert run_data["interfaces_count"] == 2
    assert "overall_score" in run_data
    assert "severity_counts" in run_data
    assert run_data["findings"] is not None
    assert len(run_data["findings"]) > 0

    # 4. Fetch project details and verify run is attached
    get_res = client.get(f"/api/projects/{proj_id}")
    assert get_res.status_code == 200
    fetched_proj = get_res.json()
    assert len(fetched_proj["runs"]) >= 1
    assert fetched_proj["runs"][0]["overall_score"] == run_data["overall_score"]

    # 5. Clean up the test project
    del_res = client.delete(f"/api/projects/{proj_id}")
    assert del_res.status_code == 200
