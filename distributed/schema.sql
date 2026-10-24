CREATE TABLE IF NOT EXISTS nf_domains (
    id text PRIMARY KEY,
    checkpoint bytea,
    config_hash text,
    last_timestamp double precision,
    work_version bigint NOT NULL DEFAULT 0,
    completed_version bigint NOT NULL DEFAULT 0,
    owner text,
    generation bigint NOT NULL DEFAULT 0,
    lease_until timestamptz,
    error text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS nf_agents (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    domain text NOT NULL REFERENCES nf_domains(id),
    key_id text UNIQUE NOT NULL,
    key_hash text NOT NULL,
    revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS nf_streams (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES nf_agents(id),
    interface text NOT NULL,
    started_at double precision NOT NULL,
    last_sequence integer,
    processed_sequence integer NOT NULL DEFAULT -1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS nf_chunks (
    id bigserial PRIMARY KEY,
    stream_id uuid NOT NULL REFERENCES nf_streams(id),
    sequence integer NOT NULL CHECK (sequence >= 0),
    sha256 text NOT NULL,
    size bigint NOT NULL,
    path text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    owner text,
    generation bigint NOT NULL DEFAULT 0,
    lease_until timestamptz,
    artifact text,
    frames integer,
    parsed_by text,
    parser_finished_at timestamptz,
    first_ts double precision,
    last_ts double precision,
    error text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(stream_id, sequence)
);
CREATE INDEX IF NOT EXISTS nf_chunks_work ON nf_chunks(status, lease_until, id);
CREATE TABLE IF NOT EXISTS nf_events (
    id text PRIMARY KEY,
    domain text NOT NULL REFERENCES nf_domains(id),
    stream_id uuid NOT NULL REFERENCES nf_streams(id),
    sequence integer NOT NULL,
    packet_index integer NOT NULL,
    timestamp double precision NOT NULL,
    reason text NOT NULL,
    target text NOT NULL,
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS nf_events_domain ON nf_events(domain, created_at, id);
CREATE TABLE IF NOT EXISTS nf_outbox (
    event_id text PRIMARY KEY REFERENCES nf_events(id),
    delivered_at timestamptz
);

ALTER TABLE nf_streams ADD COLUMN IF NOT EXISTS processed_sequence integer NOT NULL DEFAULT -1;
