# product/ -- the campaign-radar application layer.
#
# Turns scored CT observations (gold/threat_scores parquet, the detection
# pipeline's source of truth) into explainable, brand-attributed campaign leads
# held in a dedicated application Postgres (separate from Airflow's metadata DB).
#
# Modules:
#   db.py                 engine / session / Base / ping
#   models.py             SQLAlchemy ORM models (grows as the slice deepens)
#   ingest_observations.py  scored parquet -> ct_observations (upsert)  [Day 3]
#   assemble_campaigns.py    observations -> campaign clusters           [Day 4]
