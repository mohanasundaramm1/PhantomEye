# ct/ingest/stream_ct.py
#
# Read CT events from Kafka and write to local parquet ("raw" bronze layer).
# - Writes data under:   ct/data/raw/ds=YYYY-MM-DD/...
# - Uses checkpoint dir: ct/data/chk/stream_ct (for dropDuplicates + watermark)
#
# The checkpoint is KEPT across restarts by default. It holds the Kafka offsets
# already written, so keeping it is what lets a restart resume exactly where
# the last committed batch ended instead of skipping everything produced while
# the job was down. Resetting it (CT_RESET_CHK_ON_START=1) is a deliberate,
# data-losing recovery action, not a dev convenience.
#
# Environment knobs:
#   KAFKA_BOOTSTRAP_SERVERS   (default "localhost:29092")
#   KAFKA_TOPIC               (default "ct-events")
#   CT_RAW_DIR                (override raw output directory)
#   CT_CHK_DIR                (override checkpoint directory)
#   CT_DLQ_DIR                (override DLQ directory)
#   CT_MAX_OFFSETS_PER_TRIGGER (default "5000")
#   CT_RESET_CHK_ON_START     (default "0"; "1" wipes checkpoint + sink manifest)
#   CT_STARTING_OFFSETS       (default "latest"; only read when the checkpoint
#                              is empty -- e.g. '{"ct-events":{"0":24858356}}'
#                              to resume a fresh checkpoint at a known offset)
#   CT_DRIVER_MEMORY          (default "2g")
#   CT_DEBUG_CONSOLE          (default "0"; "1" also prints batches to stdout)

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

RESET_CHK = os.getenv("CT_RESET_CHK_ON_START", "0") == "1"

MAX_OFFSETS_PER_TRIGGER = os.getenv("CT_MAX_OFFSETS_PER_TRIGGER", "5000")
# Spark ignores startingOffsets whenever the checkpoint already has offsets;
# it only applies to the very first batch of a brand-new checkpoint.
STARTING_OFFSETS = os.getenv("CT_STARTING_OFFSETS", "latest")
DRIVER_MEMORY = os.getenv("CT_DRIVER_MEMORY", "2g")
DEBUG_CONSOLE = os.getenv("CT_DEBUG_CONSOLE", "0") == "1"

print("[stream_ct] -------- config --------")
print(f"[stream_ct] BOOTSTRAP={BOOTSTRAP}")
print(f"[stream_ct] TOPIC={TOPIC}")
print(f"[stream_ct] RAW OUT_DIR={OUT_DIR}")
print(f"[stream_ct] CHK CHK_DIR={CHK_DIR}")
print(f"[stream_ct] DLQ DLQ_DIR={DLQ_DIR}")
print(f"[stream_ct] CT_RESET_CHK_ON_START={int(RESET_CHK)}")
print(f"[stream_ct] CT_MAX_OFFSETS_PER_TRIGGER={MAX_OFFSETS_PER_TRIGGER}")
print(f"[stream_ct] CT_STARTING_OFFSETS={STARTING_OFFSETS} (fresh checkpoint only)")
print(f"[stream_ct] CT_DRIVER_MEMORY={DRIVER_MEMORY}")
print(f"[stream_ct] CT_DEBUG_CONSOLE={int(DEBUG_CONSOLE)}")
print("[stream_ct] ------------------------")

# Optional: reset corrupted checkpoint safely on start
#
# The parquet sink's _spark_metadata manifest (under OUT_DIR, e.g.
# ct/data/raw/_spark_metadata) is a SEPARATE structure from the checkpoint
# and is never touched by Spark's own checkpoint APIs -- it persists across
# restarts even when the checkpoint is wiped. Resetting only the checkpoint
# makes this run's FileStreamSink batch counter restart at 0 while the old
# manifest already has entries far ahead (e.g. batch 2147 from a prior run).
# Spark's sink log rejects/ignores batch ids that regress behind what it's
# already seen, so every "successful", exception-free micro-batch after a
# reset silently writes zero visible output files. Must reset both together
# or neither -- never just the checkpoint.
_raw_sink_metadata_dir = os.path.join(OUT_DIR, "_spark_metadata")
if RESET_CHK and os.path.exists(CHK_DIR):
    print(f"[stream_ct] RESET CHECKPOINT enabled → removing {CHK_DIR}")
    shutil.rmtree(CHK_DIR, ignore_errors=True)
    if os.path.exists(_raw_sink_metadata_dir):
        print(f"[stream_ct] RESET CHECKPOINT enabled → removing {_raw_sink_metadata_dir} (kept in sync with checkpoint reset)")
        shutil.rmtree(_raw_sink_metadata_dir, ignore_errors=True)

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
    # Must be set before the JVM starts (i.e. here, in a fresh process). The
    # 1g default was the ceiling the unbounded dedup state kept hitting.
    .config("spark.driver.memory", DRIVER_MEMORY)
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
    # Only used for a brand-new checkpoint (see CT_STARTING_OFFSETS above).
    .option("startingOffsets", STARTING_OFFSETS)
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
    # Dedup by id, but only remember ids for the watermark window. Plain
    # dropDuplicates(["id"]) can only evict state when the event-time column is
    # part of the key, so it kept every id ever seen in heap state until the
    # driver OOM-looped (Nov 2026). WithinWatermark keeps the same "drop repeats
    # of an id" semantics while letting state expire 10 min behind the newest
    # event_ts. Changing this operator requires a fresh checkpoint.
    .dropDuplicatesWithinWatermark(["id"])
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

# Console sink (debug only). Every started query re-reads Kafka and keeps its
# own copy of the dedup state, so this doubled memory and filled the launchd
# stdout log; opt in with CT_DEBUG_CONSOLE=1.
if DEBUG_CONSOLE:
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
