CREATE SCHEMA IF NOT EXISTS integrity_p2;

CREATE OR REPLACE FUNCTION integrity_p2.forbid_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Integrity P2 append-only relation: % forbidden', TG_OP;
END;
$$;

CREATE TABLE integrity_p2.ingest_batches (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  first_cursor bigint NOT NULL,
  last_cursor bigint NOT NULL,
  event_count integer NOT NULL CHECK (event_count > 0),
  batch_sha256 char(64) NOT NULL UNIQUE,
  previous_batch_sha256 char(64) NOT NULL DEFAULT '',
  raw_object_key text NOT NULL UNIQUE,
  raw_object_version text NOT NULL,
  bus_stream text NOT NULL,
  bus_sequence bigint NOT NULL,
  bus_replicas integer NOT NULL,
  fault_domains integer NOT NULL,
  accepted_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, namespace, edge_id, first_cursor),
  CHECK (last_cursor >= first_cursor)
);

CREATE TRIGGER ingest_batches_no_update BEFORE UPDATE ON integrity_p2.ingest_batches
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
CREATE TRIGGER ingest_batches_no_delete BEFORE DELETE ON integrity_p2.ingest_batches
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();

CREATE TABLE integrity_p2.raw_events (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  cursor bigint NOT NULL,
  event_uid text NOT NULL,
  ts_utc timestamptz NOT NULL,
  time_bucket date NOT NULL,
  cursor_bucket bigint NOT NULL,
  payload_sha256 char(64) NOT NULL,
  envelope_sha256 char(64) NOT NULL,
  previous_envelope_sha256 char(64) NOT NULL DEFAULT '',
  source_manifest_sha256 char(64) NOT NULL,
  batch_sha256 char(64) NOT NULL,
  raw_object_key text NOT NULL,
  raw_object_version text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  inserted_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, namespace, edge_id, cursor),
  UNIQUE (tenant_id, namespace, event_uid),
  CHECK (cursor > 0),
  CHECK (cursor_bucket = cursor / 1000000)
) PARTITION BY HASH (tenant_id);

DO $$
BEGIN
  FOR i IN 0..15 LOOP
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS integrity_p2.raw_events_p%s PARTITION OF integrity_p2.raw_events FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
      i, i
    );
  END LOOP;
END;
$$;

CREATE INDEX raw_events_exact_uid_idx ON integrity_p2.raw_events (tenant_id, namespace, event_uid);
CREATE INDEX raw_events_time_cursor_idx ON integrity_p2.raw_events (tenant_id, namespace, time_bucket, cursor_bucket, cursor);
CREATE INDEX raw_events_metadata_gin_idx ON integrity_p2.raw_events USING gin (metadata jsonb_path_ops);
CREATE TRIGGER raw_events_no_update BEFORE UPDATE ON integrity_p2.raw_events
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
CREATE TRIGGER raw_events_no_delete BEFORE DELETE ON integrity_p2.raw_events
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();

CREATE TABLE integrity_p2.projection_offsets (
  projection_name text NOT NULL,
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  last_cursor bigint NOT NULL DEFAULT 0,
  last_batch_sha256 char(64) NOT NULL DEFAULT '',
  updated_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (projection_name, tenant_id, namespace, edge_id)
);

CREATE TABLE integrity_p2.current_task_state (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  task_id text NOT NULL,
  last_cursor bigint NOT NULL,
  result text NOT NULL,
  summary text NOT NULL,
  details jsonb NOT NULL,
  updated_utc timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, namespace, task_id)
);

CREATE TABLE integrity_p2.dead_letters (
  dlq_id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  observed_cursor bigint,
  event_uid text,
  reason_code text NOT NULL,
  evidence jsonb NOT NULL,
  raw_object_key text,
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER dead_letters_no_update BEFORE UPDATE ON integrity_p2.dead_letters
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
CREATE TRIGGER dead_letters_no_delete BEFORE DELETE ON integrity_p2.dead_letters
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();

CREATE TABLE integrity_p2.retrieval_receipts (
  receipt_uid uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  query_sha256 char(64) NOT NULL,
  selected_event_uids text[] NOT NULL,
  route_receipt jsonb NOT NULL,
  capsule_sha256 char(64) NOT NULL,
  capsule_bytes integer NOT NULL CHECK (capsule_bytes BETWEEN 8192 AND 32768),
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  production_authority boolean NOT NULL DEFAULT false CHECK (production_authority = false)
);
CREATE TRIGGER retrieval_receipts_no_update BEFORE UPDATE ON integrity_p2.retrieval_receipts
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
CREATE TRIGGER retrieval_receipts_no_delete BEFORE DELETE ON integrity_p2.retrieval_receipts
FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();

COMMENT ON SCHEMA integrity_p2 IS 'Disposable P2 metadata/projection layer; never canonical authority';
