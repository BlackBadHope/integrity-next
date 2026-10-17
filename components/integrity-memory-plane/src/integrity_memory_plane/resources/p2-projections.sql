CREATE TABLE IF NOT EXISTS integrity_p2.projection_fts_events (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  cursor bigint NOT NULL,
  event_uid text NOT NULL,
  ts_utc timestamptz NOT NULL,
  payload_sha256 char(64) NOT NULL,
  summary text NOT NULL,
  body_text text NOT NULL,
  search_document tsvector GENERATED ALWAYS AS (to_tsvector('simple', body_text)) STORED,
  PRIMARY KEY (tenant_id, namespace, edge_id, cursor),
  UNIQUE (tenant_id, namespace, event_uid)
);
CREATE INDEX IF NOT EXISTS projection_fts_events_search_idx
  ON integrity_p2.projection_fts_events USING gin (search_document);

CREATE TABLE IF NOT EXISTS integrity_p2.projection_graph_nodes (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  node_key text NOT NULL,
  kind text NOT NULL,
  value text NOT NULL,
  PRIMARY KEY (tenant_id, namespace, node_key)
);
CREATE TABLE IF NOT EXISTS integrity_p2.projection_graph_edges (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  cursor bigint NOT NULL,
  node_key text NOT NULL,
  relation text NOT NULL,
  PRIMARY KEY (tenant_id, namespace, edge_id, cursor, node_key, relation),
  FOREIGN KEY (tenant_id, namespace, node_key)
    REFERENCES integrity_p2.projection_graph_nodes(tenant_id, namespace, node_key)
    ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS projection_graph_edges_node_idx
  ON integrity_p2.projection_graph_edges (tenant_id, namespace, node_key, cursor);

CREATE TABLE IF NOT EXISTS integrity_p2.projection_vector_events (
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  cursor bigint NOT NULL,
  event_uid text NOT NULL,
  payload_sha256 char(64) NOT NULL,
  dimensions integer NOT NULL CHECK (dimensions = 256),
  sparse_vector jsonb NOT NULL,
  norm double precision NOT NULL CHECK (norm >= 0),
  PRIMARY KEY (tenant_id, namespace, edge_id, cursor),
  UNIQUE (tenant_id, namespace, event_uid)
);

CREATE TABLE IF NOT EXISTS integrity_p2.projection_runs (
  run_uid uuid PRIMARY KEY,
  projection_name text NOT NULL,
  tenant_id text NOT NULL,
  namespace text NOT NULL,
  edge_id text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('sync','rebuild')),
  first_cursor bigint,
  last_cursor bigint NOT NULL,
  processed_events bigint NOT NULL CHECK (processed_events >= 0),
  projection_sha256 char(64) NOT NULL,
  source_batch_sha256 char(64) NOT NULL DEFAULT '',
  completed_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  production_authority boolean NOT NULL DEFAULT false CHECK (production_authority = false)
);

CREATE TABLE IF NOT EXISTS integrity_p2.gap_guard_runs (
  run_uid uuid PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('PASS','DEGRADED','FAIL')),
  committed_batches bigint NOT NULL,
  committed_events bigint NOT NULL,
  head_cursor bigint NOT NULL,
  missing_count bigint NOT NULL,
  unexplained_extra_count bigint NOT NULL,
  uid_collision_count bigint NOT NULL,
  max_versions_per_key integer NOT NULL,
  evidence_sha256 char(64) NOT NULL UNIQUE,
  evidence jsonb NOT NULL,
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  production_authority boolean NOT NULL DEFAULT false CHECK (production_authority = false)
);
DO $$ BEGIN
  CREATE TRIGGER gap_guard_runs_no_update BEFORE UPDATE ON integrity_p2.gap_guard_runs
  FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TRIGGER gap_guard_runs_no_delete BEFORE DELETE ON integrity_p2.gap_guard_runs
  FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS integrity_p2.dlq_resolutions (
  resolution_uid uuid PRIMARY KEY,
  dlq_id uuid NOT NULL REFERENCES integrity_p2.dead_letters(dlq_id),
  disposition text NOT NULL CHECK (disposition IN ('PERMANENT_QUARANTINE','REPLAYED','SUPERSEDED')),
  reason text NOT NULL,
  evidence jsonb NOT NULL,
  created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  production_authority boolean NOT NULL DEFAULT false CHECK (production_authority = false),
  UNIQUE (dlq_id, disposition)
);
DO $$ BEGIN
  CREATE TRIGGER dlq_resolutions_no_update BEFORE UPDATE ON integrity_p2.dlq_resolutions
  FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TRIGGER dlq_resolutions_no_delete BEFORE DELETE ON integrity_p2.dlq_resolutions
  FOR EACH ROW EXECUTE FUNCTION integrity_p2.forbid_mutation();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

COMMENT ON TABLE integrity_p2.projection_fts_events IS 'Disposable FTS projection rebuilt only from committed raw WORM batches';
COMMENT ON TABLE integrity_p2.projection_graph_edges IS 'Disposable graph projection rebuilt only from committed raw WORM batches';
COMMENT ON TABLE integrity_p2.projection_vector_events IS 'Disposable deterministic sparse-vector projection; never an authority';
