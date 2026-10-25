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
CREATE INDEX IF NOT EXISTS nf_chunks_received_at ON nf_chunks(created_at);
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

CREATE TABLE IF NOT EXISTS nf_incidents (
    id text PRIMARY KEY,
    incident_key text NOT NULL,
    kind text NOT NULL,
    domain text NOT NULL REFERENCES nf_domains(id),
    stream_id uuid NOT NULL REFERENCES nf_streams(id),
    sequence integer NOT NULL,
    packet_index integer NOT NULL,
    first_seen double precision NOT NULL,
    last_seen double precision NOT NULL,
    closed_at double precision,
    close_reason text,
    reason text NOT NULL,
    target text NOT NULL,
    source text NOT NULL,
    service text NOT NULL DEFAULT '',
    signal_count bigint NOT NULL DEFAULT 0,
    sources text[] NOT NULL DEFAULT '{}',
    sources_truncated boolean NOT NULL DEFAULT false,
    kinds text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (last_seen>=first_seen)
);
CREATE INDEX IF NOT EXISTS nf_incidents_key ON nf_incidents(incident_key,last_seen);
CREATE INDEX IF NOT EXISTS nf_incidents_domain ON nf_incidents(domain,updated_at DESC);
CREATE INDEX IF NOT EXISTS nf_incidents_activity ON nf_incidents(last_seen,first_seen);
CREATE INDEX IF NOT EXISTS nf_incidents_open ON nf_incidents(domain,last_seen) WHERE closed_at IS NULL;
ALTER TABLE nf_events ADD COLUMN IF NOT EXISTS incident_id text REFERENCES nf_incidents(id);
CREATE INDEX IF NOT EXISTS nf_events_incident ON nf_events(incident_id);
CREATE TABLE IF NOT EXISTS nf_incident_streams (
    incident_id text NOT NULL REFERENCES nf_incidents(id),
    stream_id uuid NOT NULL REFERENCES nf_streams(id),
    PRIMARY KEY (incident_id,stream_id)
);
CREATE TABLE IF NOT EXISTS nf_incident_outbox (
    incident_id text PRIMARY KEY REFERENCES nf_incidents(id),
    delivered_at timestamptz
);

ALTER TABLE nf_streams ADD COLUMN IF NOT EXISTS processed_sequence integer NOT NULL DEFAULT -1;

-- Web administration has separate credentials and sessions from sensor API keys.
CREATE TABLE IF NOT EXISTS nf_web_users (
    id bigserial PRIMARY KEY,
    username text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    must_change_password boolean NOT NULL DEFAULT true,
    bootstrap_hash text,
    password_version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS nf_web_sessions (
    token_hash text PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES nf_web_users(id),
    password_version integer NOT NULL,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    reauthenticated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS nf_web_sessions_user ON nf_web_sessions(user_id);
CREATE TABLE IF NOT EXISTS nf_web_login_limits (
    bucket text PRIMARY KEY,
    window_end timestamptz NOT NULL,
    attempts integer NOT NULL
);
CREATE TABLE IF NOT EXISTS nf_web_audit (
    id bigserial PRIMARY KEY,
    actor text NOT NULL,
    action text NOT NULL,
    client_ip text NOT NULL,
    subject text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS nf_web_audit_time ON nf_web_audit(created_at DESC);
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS capture_state text NOT NULL DEFAULT 'unknown';
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS backlog_bytes bigint NOT NULL DEFAULT 0;
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS backlog_files integer NOT NULL DEFAULT 0;
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS software_version text NOT NULL DEFAULT '';
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '';
ALTER TABLE nf_agents ADD COLUMN IF NOT EXISTS server_url text NOT NULL DEFAULT '';
ALTER TABLE nf_chunks ADD COLUMN IF NOT EXISTS captured_bytes bigint;
ALTER TABLE nf_chunks ADD COLUMN IF NOT EXISTS traffic_stats jsonb NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS nf_workers (
    id text PRIMARY KEY,
    kind text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Short-lived enrollment grants contain hashes only, never the operational key.
CREATE TABLE IF NOT EXISTS nf_agent_installations (
    token_hash text PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES nf_agents(id),
    key_id text NOT NULL,
    server_url text NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '15 minutes',
    used_at timestamptz
);
CREATE INDEX IF NOT EXISTS nf_agent_installations_agent ON nf_agent_installations(agent_id);
