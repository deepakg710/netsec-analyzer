"""
FastAPI REST API Routes for NetSec Analyzer.
Exposes endpoints for project management, safe file uploads, config parsing,
Packet Tracer inspection, topology reconstruction, security assessments, attack-path exploration,
before-and-after comparisons, and multi-format report downloads.
"""

import os
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel

from app.models.canonical import (
    Device, Project, AnalysisRun, Severity, FindingCategory
)
from app.ingestion.cisco_ios import CiscoIOSParser, split_multi_device_configs
from app.ingestion.packet_tracer import PacketTracerInspector
from app.topology.graph_builder import TopologyReconstructor
from app.engines.security_engine import SecurityEngine
from app.engines.attack_path_engine import AttackPathEngine
from app.engines.resilience_engine import ResilienceEngine
from app.engines.comparison_engine import ComparisonEngine
from app.reports.report_generator import ReportGenerator
from app.storage.db import StorageManager

router = APIRouter()
storage = StorageManager(base_dir=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


class ProjectCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None


class PasteConfigRequest(BaseModel):
    filename: str = "pasted_config.txt"
    config_text: str


class AttackPathRequest(BaseModel):
    source: str
    target: str
    objective: Optional[str] = "Evaluate reachability across security boundaries"
    protocol: Optional[str] = "ip"
    dst_port: Optional[int] = None


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetSec Analyzer API",
        "version": "1.0.0",
        "local_storage": storage.data_dir
    }


@router.get("/projects")
def list_projects():
    return storage.list_projects()


@router.post("/projects")
def create_project(req: ProjectCreateRequest):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Project name cannot be empty.")
    proj_id = storage.save_project(name=req.name.strip(), description=req.description)
    return {"id": proj_id, "name": req.name, "message": "Project created successfully."}


@router.get("/projects/{project_id}")
def get_project(project_id: str):
    p = storage.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found.")
    runs = storage.list_project_runs(project_id)
    p["runs"] = runs
    return p


@router.delete("/projects/{project_id}")
def delete_project(project_id: str):
    success = storage.delete_project(project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"message": "Project deleted safely."}


@router.post("/system/reset")
def reset_all_data_endpoint():
    storage.reset_all_data()
    return {"message": "All projects and analysis data have been completely wiped (0 projects)."}


@router.post("/projects/{project_id}/upload-configs")
async def upload_configs(project_id: str, files: List[UploadFile] = File(...)):
    p = storage.get_project(project_id) if project_id and project_id not in ("new", "null", "undefined", "") else None
    if not p:
        proj_name = f"Network ({files[0].filename})" if files else "Network Design"
        project_id = storage.save_project(name=proj_name, description="Auto-created from configuration files")
        p = storage.get_project(project_id)

    saved_files = p.get("source_files", [])
    parser_results = []

    for file in files:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=400, detail=f"File {file.filename} exceeds 10MB limit.")

        text_content = content.decode("utf-8", errors="ignore")
        chunks = split_multi_device_configs(text_content, file.filename)

        for chunk_name, chunk_text in chunks:
            chunk_bytes = chunk_text.encode("utf-8")
            saved_path = storage.save_uploaded_file(chunk_name, chunk_bytes)

            parser = CiscoIOSParser(filename=chunk_name)
            dev = parser.parse_text(chunk_text)

            file_meta = {
                "filename": chunk_name,
                "path": saved_path,
                "size": len(chunk_bytes),
                "device_hostname": dev.hostname,
                "device_type": dev.device_type.value,
                "interfaces_count": len(dev.interfaces),
                "warnings_count": len(parser.warnings)
            }
            saved_files.append(file_meta)
            parser_results.append(file_meta)

    # Update project source files in DB
    db = storage.SessionLocal()
    from app.storage.db import DBProject
    import json
    db_p = db.query(DBProject).filter(DBProject.id == project_id).first()
    if db_p:
        db_p.source_files_json = json.dumps(saved_files)
        db.commit()
    db.close()

    return {
        "message": f"Successfully ingested {len(parser_results)} configuration file(s).",
        "project_id": project_id,
        "parsed_files": parser_results
    }


@router.post("/projects/{project_id}/paste-config")
def paste_config(project_id: str, req: PasteConfigRequest):
    p = storage.get_project(project_id) if project_id and project_id not in ("new", "null", "undefined", "") else None
    if not p:
        proj_name = f"Project ({req.filename})"
        project_id = storage.save_project(name=proj_name, description="Auto-created from configuration snippet")
        p = storage.get_project(project_id)

    chunks = split_multi_device_configs(req.config_text, req.filename)
    saved_files = p.get("source_files", [])
    parser_results = []

    for chunk_name, chunk_text in chunks:
        chunk_bytes = chunk_text.encode("utf-8")
        saved_path = storage.save_uploaded_file(chunk_name, chunk_bytes)

        parser = CiscoIOSParser(filename=chunk_name)
        dev = parser.parse_text(chunk_text)

        file_meta = {
            "filename": chunk_name,
            "path": saved_path,
            "size": len(chunk_bytes),
            "device_hostname": dev.hostname,
            "device_type": dev.device_type.value,
            "interfaces_count": len(dev.interfaces),
            "warnings_count": len(parser.warnings)
        }
        saved_files.append(file_meta)
        parser_results.append(file_meta)

    db = storage.SessionLocal()
    from app.storage.db import DBProject
    import json
    db_p = db.query(DBProject).filter(DBProject.id == project_id).first()
    if db_p:
        db_p.source_files_json = json.dumps(saved_files)
        db.commit()
    db.close()

    return {
        "message": f"Successfully ingested {len(chunks)} device configuration(s).",
        "project_id": project_id,
        "device": parser_results[0] if parser_results else None,
        "parsed_files": parser_results
    }


@router.post("/projects/{project_id}/upload-pkt")
async def upload_packet_tracer_file(project_id: str, file: UploadFile = File(...)):
    content = await file.read()
    inspector = PacketTracerInspector(filename=file.filename)
    report = inspector.inspect_and_parse(content)

    resolved_project_id = project_id if project_id and project_id not in ("new", "null", "undefined", "") else None

    # If any devices were extracted, save them to the project
    if report.extracted_devices:
        p = storage.get_project(resolved_project_id) if resolved_project_id else None
        if not p:
            proj_name = f"Packet Tracer ({file.filename})"
            resolved_project_id = storage.save_project(name=proj_name, description=f"Extracted from {file.filename}")
            p = storage.get_project(resolved_project_id)

        saved_files = p.get("source_files", [])
        for dev in report.extracted_devices:
            raw_text = dev.raw_config or f"hostname {dev.hostname}"
            saved_path = storage.save_uploaded_file(f"{dev.hostname}.txt", raw_text.encode("utf-8"))
            saved_files.append({
                "filename": f"{dev.hostname}.txt",
                "path": saved_path,
                "size": len(raw_text),
                "device_hostname": dev.hostname,
                "device_type": dev.device_type.value,
                "interfaces_count": len(dev.interfaces),
                "warnings_count": len(dev.parser_warnings)
            })
        
        db = storage.SessionLocal()
        from app.storage.db import DBProject
        import json
        db_p = db.query(DBProject).filter(DBProject.id == resolved_project_id).first()
        if db_p:
            db_p.source_files_json = json.dumps(saved_files)
            db.commit()
        db.close()

    res = report.to_dict()
    res["project_id"] = resolved_project_id
    return res


@router.post("/projects/{project_id}/analyze")
def run_analysis(project_id: str):
    p = storage.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found.")

    source_files = p.get("source_files", [])
    if not source_files:
        raise HTTPException(
            status_code=400,
            detail="No configuration files uploaded. Please import Cisco configs or Packet Tracer data first."
        )

    # 1. Parse all configuration files
    devices: List[Device] = []
    all_warnings: List[str] = []

    for sf in source_files:
        path = sf["path"]
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            parser = CiscoIOSParser(filename=sf["filename"])
            dev = parser.parse_text(content)
            devices.append(dev)
            all_warnings.extend(parser.warnings)

    if not devices:
        raise HTTPException(status_code=400, detail="Failed to parse any valid devices from provided files.")

    # 2. Topology reconstruction
    reconstructor = TopologyReconstructor(devices)
    topology_data = reconstructor.build_topology()

    # 3. Security Analysis
    sec_engine = SecurityEngine(devices, reconstructor.links)
    findings, overall_score, coverage_score, cat_scores, sev_counts = sec_engine.run_assessment()

    # Determine risk level label
    if overall_score >= 85:
        risk_level = "Low Risk"
    elif overall_score >= 65:
        risk_level = "Moderate Risk"
    elif overall_score >= 45:
        risk_level = "High Risk"
    else:
        risk_level = "Critical Risk"

    # 4. Generate Top Priority Fixes (Critical & High)
    top_fixes = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:5]

    # 5. Default Attack Paths (e.g. from lowest security VLAN or user switch to core/server)
    path_engine = AttackPathEngine(devices, reconstructor.links, reconstructor.graph)
    sample_paths = []
    if len(devices) >= 2:
        src_dev = devices[-1].hostname  # usually switch or edge
        dst_dev = devices[0].hostname   # usually router or firewall
        ap = path_engine.analyze_path(src_dev, dst_dev, objective="Assess path to management gateway")
        sample_paths.append(ap)

    # Category counts
    cat_counts: Dict[str, int] = {}
    for f in findings:
        c_name = f.category.value
        cat_counts[c_name] = cat_counts.get(c_name, 0) + 1

    run_id = f"run_{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow().isoformat() + "Z"

    total_interfaces = sum(len(d.interfaces) for d in devices)

    run_obj = AnalysisRun(
        id=run_id,
        project_id=project_id,
        timestamp=now,
        overall_score=overall_score,
        risk_level=risk_level,
        coverage_score=coverage_score,
        category_scores=cat_scores,
        severity_counts=sev_counts,
        category_counts=cat_counts,
        devices_count=len(devices),
        interfaces_count=total_interfaces,
        findings=findings,
        top_priority_fixes=top_fixes,
        attack_paths=sample_paths,
        topology=topology_data,
        parser_warnings=all_warnings,
        unsupported_features=[]
    )

    storage.save_run(project_id, run_obj.model_dump())
    return run_obj.model_dump()


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    r = storage.get_run(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return r


@router.post("/runs/{run_id}/attack-path")
def calculate_attack_path(run_id: str, req: AttackPathRequest):
    r = storage.get_run(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="Analysis run not found.")

    project_id = r["project_id"]
    p = storage.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found.")

    # Reconstruct devices
    devices = []
    for sf in p.get("source_files", []):
        if os.path.exists(sf["path"]):
            with open(sf["path"], "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            parser = CiscoIOSParser(filename=sf["filename"])
            devices.append(parser.parse_text(content))

    reconstructor = TopologyReconstructor(devices)
    reconstructor.build_topology()

    path_engine = AttackPathEngine(devices, reconstructor.links, reconstructor.graph)
    ap = path_engine.analyze_path(
        src_query=req.source,
        dst_query=req.target,
        objective=req.objective or "Evaluate reachability across boundaries",
        protocol=req.protocol or "ip",
        dst_port=req.dst_port
    )
    return ap.dict()


@router.get("/runs/{run_id}/resilience")
def get_resilience_analysis(run_id: str):
    r = storage.get_run(run_id)
    if not r:
        raise HTTPException(status_code=404, detail="Analysis run not found.")

    p = storage.get_project(r["project_id"])
    devices = []
    for sf in p.get("source_files", []):
        if os.path.exists(sf["path"]):
            with open(sf["path"], "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            parser = CiscoIOSParser(filename=sf["filename"])
            devices.append(parser.parse_text(content))

    reconstructor = TopologyReconstructor(devices)
    reconstructor.build_topology()

    res = ResilienceEngine.analyze(devices, reconstructor.links, reconstructor.graph)
    return res.to_dict()


@router.get("/compare/{run_a_id}/{run_b_id}")
def compare_runs(run_a_id: str, run_b_id: str):
    dict_a = storage.get_run(run_a_id)
    dict_b = storage.get_run(run_b_id)

    if not dict_a or not dict_b:
        raise HTTPException(status_code=404, detail="One or both analysis runs not found.")

    run_a = AnalysisRun(**dict_a)
    run_b = AnalysisRun(**dict_b)

    cmp_res = ComparisonEngine.compare_runs(run_a, run_b)
    return cmp_res.to_dict()


@router.get("/runs/{run_id}/report")
def download_report(run_id: str, format: str = "html"):
    r_dict = storage.get_run(run_id)
    if not r_dict:
        raise HTTPException(status_code=404, detail="Analysis run not found.")

    run = AnalysisRun(**r_dict)
    p_dict = storage.get_project(run.project_id)
    project = Project(**p_dict)

    rep_gen = ReportGenerator(project, run)

    if format.lower() == "json":
        json_content = rep_gen.generate_json()
        return JSONResponse(content=json.loads(json_content))

    elif format.lower() == "pdf":
        pdf_path = os.path.join(storage.reports_dir, f"report_{run_id}.pdf")
        rep_gen.generate_pdf(pdf_path)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"NetSec_Report_{project.name}_{run_id}.pdf"
        )

    else:  # HTML default
        html_content = rep_gen.generate_html()
        return HTMLResponse(content=html_content)
