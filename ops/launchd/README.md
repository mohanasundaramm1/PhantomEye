# PhantomEye process supervision (`ops/launchd/`)

This directory makes the **real-time CT ingestion lane self-healing** on macOS.

## The problem it solves

The CT lane is a chain:

```
certstream (Docker)  ->  forwarder.py  ->  Kafka (Docker)  ->  stream_ct.py  ->  ct/data/raw/*.parquet
                          ^^^^^^^^^^^^                          ^^^^^^^^^^^^^
                          host process                         host process (Spark)
```

`forwarder.py` and `stream_ct.py` were run by hand (`make forward-ct`,
`make stream-ct`) as foreground processes. When either died — a crash, a closed
terminal, an OOM, or (most commonly) the laptop going to sleep — **nothing
restarted it, and nothing alerted anyone.** A real 8-hour ingestion outage went
completely unnoticed until a downstream freshness gate failed. Everything the
product shows depends on this lane, so a silent stall makes the whole dashboard
quietly wrong.

## What gets installed

Four launchd **user agents** (they run as you, on login — no root, no `sudo`):

| Agent | Type | What it does |
|---|---|---|
| `com.phantomeye.forwarder` | `KeepAlive` | Keeps `forwarder.py` alive; restarts on crash, starts on login/boot/wake. |
| `com.phantomeye.stream-ct` | `KeepAlive` | Same for the Spark `stream_ct.py` consumer. Runs with `SPARK_LOCAL_IP=127.0.0.1` and `CT_RESET_CHK_ON_START=0` so restarts **resume** from the last Kafka offset instead of dropping data. |
| `com.phantomeye.freshness-watchdog` | `StartInterval` (5 min) | Runs `scripts/ct_freshness_watchdog.py`. If no fresh CT data has landed in >60 min, it fires a macOS notification. This is the safety net for a process that is *alive but not producing output* — the one thing `KeepAlive` cannot detect. |
| `com.phantomeye.log-rotate` | `StartInterval` (15 min) | Runs `rotate_logs.sh`, capping each of the two `KeepAlive` agents' stdout/stderr logs at 50 MB (5 gzipped backups kept per file, `LOG_ROTATE_KEEP`). Found live: `forwarder.err.log` grew to **178 GB** with nothing rotating it, down to 5.3 GB free on disk. Uses copytruncate (truncates the same inode in place), not rename-and-recreate — both agents hold their log fd open for their whole lifetime, so a rename would leave them writing into a detached, invisible file forever. It also prunes the forwarder's low-priority spool (`ct/data/low_priority/ds=*.jsonl`, ~11 GB/day once the forwarder keeps up with CertStream) to the last 7 days (`SPOOL_KEEP_DAYS`) via `prune_spool.sh`; today's file is never touched, and `SPOOL_PRUNE_DRY_RUN=1` lists what would go without deleting. |

The `*.plist.template` files are portable (they contain `__PLACEHOLDERS__`).
`install.sh` renders them with this machine's real repo path, venv Python,
`JAVA_HOME`, and `PATH`, writes the results to `~/Library/LaunchAgents/`, and
loads them.

## Usage

```bash
make supervise-install     # render + load all four agents (idempotent)
make supervise-status      # show state/pid of each agent + last watchdog result
make supervise-uninstall   # stop + remove all four agents
```

Logs land in `ops/launchd/logs/` (gitignored):
`forwarder.out.log`, `stream-ct.out.log`, `watchdog.out.log`, etc.

## Important notes

- **These are standing login agents.** Once installed they start automatically
  every time you log in, until you run `make supervise-uninstall`. That is the
  point (survive reboots), but it means they persist beyond one session.
- **Docker still supervises the infra half.** Kafka, Zookeeper, Kafdrop, and
  certstream run under Docker with `restart: unless-stopped` (see the root
  `docker-compose.yml`). launchd covers the two *host* processes; Docker covers
  the containers. Clean split: **Docker = infrastructure, launchd = the two app
  daemons.**
- **Don't also run `make forward-ct` / `make stream-ct` by hand** while the
  agents are installed — you'd get duplicate producers, or two Spark consumers
  fighting over one checkpoint. `install.sh` stops any manual copies for you,
  but don't start new ones afterward.
- **Not for production.** launchd is the right answer for this macOS laptop.
  A server deployment would move these to systemd units or containers; the
  templates map cleanly onto either.
