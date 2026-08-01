# Proxmox Soft Backup 0.9.2

PSB 0.9.2 introduces the first narrowly-scoped Safe Recovery executor.

## Supported execute target

Only this target is enabled:

- application: `grafana`
- component: `database`
- source/target: `/var/lib/grafana`
- service: `grafana-server.service`

All other applications, components, and host configuration remain preview-only.

## Install

```bash
chmod +x install.sh
./install.sh
psb --version
```

## Preview

```bash
psb recover /path/to/backup.psb
```

## Safe execution

First inspect and clear any previous test lock:

```bash
psb recovery-status
psb recovery-abort
```

Then run:

```bash
psb recover /path/to/backup.psb \
  --application grafana \
  --component database \
  --execute \
  --rollback-destination /path/to/rollback-storage
```

PSB will:

1. Verify the source backup.
2. Rebuild the recovery preview.
3. Select exactly one Grafana database component.
4. Create and verify a rollback `.psbr` from the current `/var/lib/grafana`.
5. Re-check that the source and current state did not change.
6. Require three interactive confirmations.
7. Stop `grafana-server.service` if it was active.
8. Install the backed-up Grafana database directory.
9. Verify the installed component checksum before restarting Grafana.
10. Start Grafana and check service state.
11. Record the completed operation in `recovery.lock`.

If any step fails after the current directory was moved, PSB automatically restores the previous directory and restarts Grafana.

## Required confirmations

The operator must type exactly:

```text
YES
RESTORE
RESTORE GRAFANA DATABASE
```

Execution requires an interactive terminal. There is no non-interactive bypass in 0.9.2.

## Recovery lock

```bash
psb recovery-status
psb recovery-abort
```

`recovery-abort` removes only the lock. It never deletes rollback packages.

## Safety boundaries

- One component per run.
- No host recovery.
- No InfluxDB recovery.
- No force mode.
- No identical-file overwrite mode yet.
- Existing recovery lock blocks a new execution.
- Rollback must be created and verified before confirmations and system modification.

## v0.9.4 Recovery Stabilization

- Grafana HTTP health uses Python urllib only; external curl is not used.
- Health check retries for up to 30 seconds and records attempts and wait time.
- Recovery lock and result record operation duration.
- New command: `psb doctor recovery` (or `--json`).
- Safe execute scope remains limited to `grafana/database`.


## InfluxDB database Safe Recovery

Version 0.9.4 adds the second production-gated execution target:

```bash
psb recover BACKUP.psb \
  --application influxdb \
  --component database \
  --execute \
  --rollback-destination /mnt/4ProxmoxBackup
```

The exact third confirmation is `RESTORE INFLUXDB DATABASE`. InfluxDB services that were active before recovery are stopped before the rollback snapshot, restarted afterward, and checked through `http://127.0.0.1:8086/ping` using Python urllib. All other components remain preview-only.
