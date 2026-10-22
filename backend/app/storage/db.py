"""
Local SQLite persistence layer and safe storage management for NetSec Analyzer.
Manages projects, analysis run histories, safe upload isolation, and report assets.
"""

import os
import json
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class DBProject(Base):
    __tablename__ = "projects"
    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(String(64), nullable=False)
    updated_at = Column(String(64), nullable=False)
    source_files_json = Column(Text, default="[]")


class DBAnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), nullable=False)
    timestamp = Column(String(64), nullable=False)
    overall_score = Column(Integer, default=0)
    risk_level = Column(String(64), default="Low")
    coverage_score = Column(Integer, default=0)
    devices_count = Column(Integer, default=0)
    interfaces_count = Column(Integer, default=0)
    run_data_json = Column(Text, nullable=False)


class StorageManager:
    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        self.data_dir = os.path.join(self.base_dir, "data")
        self.uploads_dir = os.path.join(self.data_dir, "uploads")
        self.reports_dir = os.path.join(self.data_dir, "reports")
        
        os.makedirs(self.uploads_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        db_path = os.path.join(self.data_dir, "netsec_analyzer.db")
        self.engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def save_project(self, name: str, description: Optional[str] = None, files: Optional[List[Dict[str, Any]]] = None) -> str:
        project_id = f"proj_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        files_json = json.dumps(files or [])
        
        db = self.SessionLocal()
        try:
            db_proj = DBProject(
                id=project_id,
                name=name,
                description=description,
                created_at=now,
                updated_at=now,
                source_files_json=files_json
            )
            db.add(db_proj)
            db.commit()
            return project_id
        finally:
            db.close()

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        db = self.SessionLocal()
        try:
            p = db.query(DBProject).filter(DBProject.id == project_id).first()
            if not p:
                return None
            return {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "created_at": p.created_at,
                "updated_at": p.updated_at,
                "source_files": json.loads(p.source_files_json or "[]")
            }
        finally:
            db.close()

    def list_projects(self) -> List[Dict[str, Any]]:
        db = self.SessionLocal()
        try:
            projs = db.query(DBProject).order_by(DBProject.updated_at.desc()).all()
            result = []
            for p in projs:
                last_run = db.query(DBAnalysisRun).filter(DBAnalysisRun.project_id == p.id).order_by(DBAnalysisRun.timestamp.desc()).first()
                result.append({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                    "source_files_count": len(json.loads(p.source_files_json or "[]")),
                    "last_score": last_run.overall_score if last_run else None,
                    "last_risk_level": last_run.risk_level if last_run else None,
                    "last_run_id": last_run.id if last_run else None
                })
            return result
        finally:
            db.close()

    def delete_project(self, project_id: str) -> bool:
        db = self.SessionLocal()
        try:
            p = db.query(DBProject).filter(DBProject.id == project_id).first()
            if not p:
                return False
            db.query(DBAnalysisRun).filter(DBAnalysisRun.project_id == project_id).delete()
            db.delete(p)
            db.commit()
            return True
        finally:
            db.close()

    def save_run(self, project_id: str, run_dict: Dict[str, Any]) -> str:
        run_id = run_dict.get("id") or f"run_{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat() + "Z"
        
        db = self.SessionLocal()
        try:
            db_run = DBAnalysisRun(
                id=run_id,
                project_id=project_id,
                timestamp=now,
                overall_score=run_dict.get("overall_score", 0),
                risk_level=run_dict.get("risk_level", "Low"),
                coverage_score=run_dict.get("coverage_score", 0),
                devices_count=run_dict.get("devices_count", 0),
                interfaces_count=run_dict.get("interfaces_count", 0),
                run_data_json=json.dumps(run_dict)
            )
            db.add(db_run)
            
            # Update project updated_at
            p = db.query(DBProject).filter(DBProject.id == project_id).first()
            if p:
                p.updated_at = now
            
            db.commit()
            return run_id
        finally:
            db.close()

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        db = self.SessionLocal()
        try:
            r = db.query(DBAnalysisRun).filter(DBAnalysisRun.id == run_id).first()
            if not r:
                return None
            return json.loads(r.run_data_json)
        finally:
            db.close()

    def list_project_runs(self, project_id: str) -> List[Dict[str, Any]]:
        db = self.SessionLocal()
        try:
            runs = db.query(DBAnalysisRun).filter(DBAnalysisRun.project_id == project_id).order_by(DBAnalysisRun.timestamp.desc()).all()
            return [
                {
                    "id": r.id,
                    "project_id": r.project_id,
                    "timestamp": r.timestamp,
                    "overall_score": r.overall_score,
                    "risk_level": r.risk_level,
                    "coverage_score": r.coverage_score,
                    "devices_count": r.devices_count,
                    "interfaces_count": r.interfaces_count
                }
                for r in runs
            ]
        finally:
            db.close()

    def save_uploaded_file(self, filename: str, content: bytes) -> str:
        """Saves an uploaded file with safe UUID filename outside public paths."""
        safe_name = f"{uuid.uuid4().hex}_{os.path.basename(filename)}"
        target_path = os.path.join(self.uploads_dir, safe_name)
        with open(target_path, "wb") as f:
            f.write(content)
        return target_path

    def reset_all_data(self) -> None:
        """Safely wipes all projects, runs, uploads, and generated reports to reset to 0."""
        db = self.SessionLocal()
        try:
            db.query(DBAnalysisRun).delete()
            db.query(DBProject).delete()
            db.commit()
        finally:
            db.close()

        for folder in [self.uploads_dir, self.reports_dir]:
            if os.path.exists(folder):
                for fname in os.listdir(folder):
                    try:
                        p = os.path.join(folder, fname)
                        if os.path.isfile(p):
                            os.remove(p)
                    except Exception:
                        pass

