FROM apache/airflow:2.9.3

USER root
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*

USER airflow

# Bake the pipeline's Python dependencies into the image so the containers
# don't re-run a multi-minute pip install on every start (this replaces the
# per-service _PIP_ADDITIONAL_REQUIREMENTS env var — same package set). Only
# great_expectations is pinned (<1.0), matching the code's use of the legacy
# ge.from_pandas API removed in GE 1.0.
RUN pip install --no-cache-dir \
    psycopg2-binary pandas pyarrow requests dnspython tldextract \
    great_expectations==0.18.12 scikit-learn scipy lightgbm joblib
