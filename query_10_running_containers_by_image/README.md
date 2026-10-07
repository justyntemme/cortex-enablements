# Query 10: running containers for one image

Query 10 returns the distinct containers whose newest XDR telemetry record in
the selected time window reports a running state for a specified image.

It does **not** infer runtime state from `asset_inventory.xdm.asset.last_observed`.
The state comes from the XDR agent's container metadata at
`actor_container_info.other.state` (with `State` supported as a provider-case
fallback). The query normalizes both observed running values,
`CONTAINER_RUNNING` and `running`, and filters only after retaining the newest
record for each `(agent_id, container_id)` pair.

The preferred input is the Cortex image asset ID in the `id` field emitted by
Queries 8 and 9:

```bash
python3 query_10_running_containers_by_image/main.py \
  --image-id <CORTEX_IMAGE_ASSET_ID>
```

The script also accepts a config digest or an image reference containing one:

```bash
python3 query_10_running_containers_by_image/main.py \
  --image-id sha256:<CONFIG_DIGEST>
```

For a Cortex asset ID, a small XQL query first resolves the requested asset's
`xdm.image.identifier`. The script then places that config digest in an early
filter on `actor_container_info.image_id`. This two-stage keyed lookup is the
logical join between the asset and telemetry collections, but avoids a broad
runtime join over a large `xdr_data` collection. It also avoids confusing the
Cortex asset ID, the image config digest, and the manifest digest.

The default telemetry window is 24 hours. Increase `--relative-time-ms` for
quiet containers that may not have produced an event in that period. The
result is bounded by the selected XDR telemetry window: a container with no
telemetry record in that window cannot be returned by this dataset.

Use `--show-query` to print the exact generated XQL to standard error. The
script follows Cortex's result-stream response when the inline response is too
large and requests up to 1,000,000 rows by default.
