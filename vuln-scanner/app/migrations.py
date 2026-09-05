from sqlalchemy import inspect, text
from .database import engine

def migrate_legacy_schema():
    # Lightweight compatibility migration for the original portfolio prototype.
    # New deployments should use a real migration tool before production rollout.
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if "findings" in tables:
        cols = {c["name"] for c in inspector.get_columns("findings")}
        with engine.begin() as conn:
            if "cvss_score" not in cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN cvss_score FLOAT"))
            if "cvss_vector" not in cols:
                conn.execute(text("ALTER TABLE findings ADD COLUMN cvss_vector VARCHAR(120)"))
