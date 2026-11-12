# CloudWatch source evaluation

Deploy the central runtime first. Its normalization setup maps `cloud_soc.recovery_mode`, and its detection staging omits records already evaluated by the source worker. The central AWS detector handles new CloudTrail management events. The recovery worker evaluates historical CloudTrail events with the three revision-pinned AWS rules. VPC and WAF workers evaluate their own rule and keep matches with the original record for review.

Run one Compose project per source with a separate state directory owned by UID 1000. Set the values in an operator-owned environment file outside the repository. Set the endpoint network to a Docker network where `https://elasticsearch:9200` resolves with the supplied CA.

| Variable | Value |
| --- | --- |
| `SOC_CW_RUNTIME_IMAGE` | Reviewed central runtime image containing these source files |
| `SOC_CW_ENTRYPOINT` | `worker.py` for CloudTrail or `network_waf.py` for VPC and WAF |
| `SOC_CW_KIND` | `cloudtrail`, `vpc` or `waf` |
| `SOC_CW_LOG_GROUP`, `SOC_CW_REGION`, `SOC_CW_ACCOUNT_ID` | Exact CloudWatch Logs source scope |
| `SOC_CW_ORGANIZATION` | Existing organization on the corresponding Filebeat intake |
| `SOC_CW_HISTORY_START` | Offset-aware history start, e.g. `2026-01-01T00:00:00Z` |
| `SOC_CW_STATE_DIR` | Dedicated persistent directory per worker |
| `SOC_CW_ES_KEY_FILE`, `SOC_CW_ES_CA_FILE` | Protected Elasticsearch key and CA paths |

The instance role needs `logs:FilterLogEvents` for the specified log group. The Elasticsearch key needs read on `soc-host-raw-linux-*`, read and create_doc on `soc-normalized-v1`, read and index on `soc-processing-v1`, and create_doc on `soc-detection-runs-v1`. CloudTrail also needs create_doc on `security-alerts`. Keep both credentials and checkpoints outside Git.

```sh
docker compose --env-file /path/to/source.env -p cloud-soc-cw-source \
  -f deploy/aws/cloudwatch_recovery/compose.yaml up -d
```

The worker keeps history and live checkpoints in `progress.sqlite`. It matches CloudWatch event ID, stream and timestamp to existing Filebeat intake, creates normalized metadata and connects the evaluation to the original processing record. A missing original or rejected format is counted in the worker status output. VPC `NODATA` is not applicable and `SKIPDATA` is not evaluable. WAF preserves action and rule classification while request bodies, cookies, headers and match values stay at the source.
