# ct/ingest/stream_ct.py
#
# Read CT events from Kafka and write to local parquet ("raw" bronze layer).
# - Writes data under:   ct/data/raw/ds=YYYY-MM-DD/...
# - Uses checkpoint dir: ct/data/chk/stream_ct (for dropDuplicates + watermark)
#
# For local development we *default* to resetting the checkpoint on every start
# to avoid corrupted state after crashes / laptop sleep:
#   CT_RESET_CHK_ON_START=1  (default)
#
# If you ever want to preserve state across restarts, run with:
#   CT_RESET_CHK_ON_START=0
#
# Environment knobs:
#   KAFKA_BOOTSTRAP_SERVERS   (default "localhost:29092")
#   KAFKA_TOPIC               (default "ct-events")
#   CT_RAW_DIR                (override raw output directory)
#   CT_CHK_DIR                (override checkpoint directory)
#   CT_DLQ_DIR                (override DLQ directory)
#   CT_MAX_OFFSETS_PER_TRIGGER (default "5000")
#   CT_RESET_CHK_ON_START     (default "1"  -> reset checkpoints at start)

import os
import shutil

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    from_json,
    to_timestamp,
    current_timestamp,
    expr,
    lit,
    to_date,
)
from pyspark.sql.types import (
    StructType,
    StructField,
    StringType,
    DoubleType,
    ArrayType,
)

# ---------- paths ----------

THIS_DIR = os.path.dirname(__file__)
CT_DIR = os.path.abspath(os.path.join(THIS_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(CT_DIR, ".."))
DATA_DIR = os.path.join(CT_DIR, "data")

RAW_DIR_DEFAULT = os.path.join(DATA_DIR, "raw")
DLQ_DIR_DEFAULT = os.path.join(DATA_DIR, "dlq", "bad_json")
CHK_DIR_DEFAULT = os.path.join(DATA_DIR, "chk", "stream_ct")

# Make sure base dirs exist
os.makedirs(RAW_DIR_DEFAULT, exist_ok=True)
os.makedirs(os.path.dirname(DLQ_DIR_DEFAULT), exist_ok=True)
os.makedirs(os.path.dirname(CHK_DIR_DEFAULT), exist_ok=True)

# ---------- env / config ----------

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "ct-events")

OUT_DIR = os.getenv("CT_RAW_DIR", RAW_DIR_DEFAULT)
CHK_DIR = os.getenv("CT_CHK_DIR", CHK_DIR_DEFAULT)
DLQ_DIR = os.getenv("CT_DLQ_DIR", DLQ_DIR_DEFAULT)

# IMPORTANT: default to *resetting* checkpoint on start for local dev
RESET_CHK = os.getenv("CT_RESET_CHK_ON_START", "1") == "1"

MAX_OFFSETS_PER_TRIGGER = os.getenv("CT_MAX_OFFSETS_PER_TRIGGER", "5000")

print("[stream_ct] -------- config --------")
print(f"[stream_ct] BOOTSTRAP={BOOTSTRAP}")
print(f"[stream_ct] TOPIC={TOPIC}")
print(f"[stream_ct] RAW OUT_DIR={OUT_DIR}")
print(f"[stream_ct] CHK CHK_DIR={CHK_DIR}")
print(f"[stream_ct] DLQ DLQ_DIR={DLQ_DIR}")
print(f"[stream_ct] CT_RESET_CHK_ON_START={int(RESET_CHK)}")
print(f"[stream_ct] CT_MAX_OFFSETS_PER_TRIGGER={MAX_OFFSETS_PER_TRIGGER}")
print("[stream_ct] ------------------------")

# Optional: reset corrupted checkpoint safely on start
if RESET_CHK and os.path.exists(CHK_DIR):
    print(f"[stream_ct] RESET CHECKPOINT enabled → removing {CHK_DIR}")
    shutil.rmtree(CHK_DIR, ignore_errors=True)

# Ensure checkpoint directory exists after optional reset
os.makedirs(CHK_DIR, exist_ok=True)

# ---------- schema ----------

schema = StructType(
    [
        StructField("id", StringType(), False),
        StructField("domain", StringType(), False),
        StructField("tld", StringType(), True),
        StructField("event_ts", StringType(), False),
        StructField("producer_ts", StringType(), False),
        StructField("source", StringType(), False),
        # attached by the forwarder's local triage pass (nullable for
        # backward compatibility with pre-triage events)
        StructField("triage_score", DoubleType(), True),
        StructField("triage_reasons", ArrayType(StringType()), True),
    ]
)

# ---------- Spark session ----------

spark = (
    SparkSession.builder.appName("CT->Raw")
    .config("spark.sql.shuffle.partitions", "4")
    .config("spark.sql.session.timeZone", "UTC")
    .config("spark.sql.streaming.stateStore.maintenanceInterval", "60s")
    .config("spark.sql.streaming.minBatchesToRetain", "5")
    .config("spark.sql.streaming.multipleWatermarkPolicy", "min")
    .config(
        "spark.jars.packages",
        "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1",
    )
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")

# ---------- streaming pipeline ----------

raw = (
    spark.readStream.format("kafka")
    .option("kafka.bootstrap.servers", BOOTSTRAP)
    .option("subscribe", TOPIC)
    # Start from latest offsets when job starts
    .option("startingOffsets", "latest")
    # Don't fail if some offsets are missing (e.g. Kafka log retention)
    .option("failOnDataLoss", "false")
    # Group id only for this consumer (careful not to reuse from other jobs)
    .option("kafka.group.id", "ct-stream")
    .option("fetchOffset.retryIntervalMs", "1000")
    .option("fetchOffset.numRetries", "60")
    .option("kafkaConsumer.pollTimeoutMs", "120000")
    .option("maxOffsetsPerTrigger", MAX_OFFSETS_PER_TRIGGER)
    .load()
)

df = raw.selectExpr("CAST(value AS STRING) AS value", "timestamp AS kafka_ts")
parsed = df.withColumn("json", from_json(col("value"), schema))

good = (
    parsed.where(col("json").isNotNull())
    .select(
        col("json.id").alias("id"),
        col("json.domain").alias("domain"),
        col("json.tld").alias("tld"),
        to_timestamp(col("json.event_ts")).alias("event_ts"),
        to_timestamp(col("json.producer_ts")).alias("producer_ts"),
        col("json.source").alias("source"),
        col("json.triage_score").alias("triage_score"),
        col("json.triage_reasons").alias("triage_reasons"),
        current_timestamp().alias("ingest_ts"),
    )
    .withColumn(
        "latency_sec",
        expr("ROUND(unix_timestamp(ingest_ts) - unix_timestamp(event_ts), 3)"),
    )
    .withWatermark("event_ts", "10 minutes")
    # NOTE: this is what requires checkpoint / state store
    .dropDuplicates(["id"])
    .withColumn("ds", to_date(col("event_ts")))
)

bad = (
    parsed.where(col("json").isNull())
    .select(
        col("value"),
        lit("json_parse_failed").alias("reason"),
        current_timestamp().alias("ig_ts"),
    )
)

# Console sink (debug)
(
    good.writeStream.format("console")
    .outputMode("append")
    .option("truncate", "false")
    .trigger(processingTime="5 seconds")
    .queryName("ct_console")
    .start()
)

# Main bronze parquet sink
(
    good.writeStream.format("parquet")
    .option("path", OUT_DIR)
    .option("checkpointLocation", CHK_DIR)
    .option("compression", "snappy")
    .partitionBy("ds")
    .outputMode("append")
    .trigger(processingTime="5 seconds")
    .queryName("ct_raw_sink")
    .start()
)

# DLQ sink for bad JSON
(
    bad.writeStream.format("parquet")
    .option("path", DLQ_DIR)
    .option("checkpointLocation", CHK_DIR + "_dlq")
    .outputMode("append")
    .trigger(processingTime="5 seconds")
    .queryName("ct_dlq_sink")
    .start()
)

print("[stream_ct] streaming queries started, awaiting termination...")
spark.streams.awaitAnyTermination()
