BEGIN;

CREATE SCHEMA IF NOT EXISTS daos_memory;

CREATE TABLE daos_memory.agent_registry (
    agent_id text PRIMARY KEY CHECK (agent_id ~ '^[a-z][a-z0-9_-]{1,31}$'),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
    role_categories text[] NOT NULL DEFAULT '{}',
    allowed_memory_types text[] NOT NULL DEFAULT '{}',
    bootstrap_key_hash text,
    bootstrap_expires_at timestamptz,
    bootstrap_uses_remaining smallint NOT NULL DEFAULT 0 CHECK (bootstrap_uses_remaining BETWEEN 0 AND 5),
    access_token_hash text,
    access_expires_at timestamptz,
    last_access_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE daos_memory.canonical_policies (
    id uuid PRIMARY KEY,
    category text NOT NULL CHECK (category IN ('GLOBAL','MEMORY_WRITE','STRATEGY','DEVELOPMENT','EXECUTION','RESEARCH')),
    title varchar(240) NOT NULL,
    content varchar(8000) NOT NULL,
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUPERSEDED','DRAFT')),
    priority smallint NOT NULL DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
    supersedes_id uuid REFERENCES daos_memory.canonical_policies(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE daos_memory.context_events (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    actor varchar(80) NOT NULL,
    actor_role varchar(80) NOT NULL,
    source_interface varchar(80) NOT NULL,
    product varchar(120) NOT NULL,
    topic varchar(160) NOT NULL,
    thread_id varchar(160),
    work_id varchar(160),
    memory_type varchar(80) NOT NULL,
    event_type varchar(80) NOT NULL,
    title varchar(240) NOT NULL,
    summary varchar(1200) NOT NULL,
    content varchar(8000) NOT NULL,
    status text NOT NULL CHECK (status IN ('CURRENT','SUPERSEDED','DRAFT')),
    authority_level text NOT NULL CHECK (authority_level IN ('OWNER_DECISION','VERIFIED_EVIDENCE','OPERATIONAL_STATE','AGENT_ASSESSMENT','HYPOTHESIS')),
    source_ref varchar(500),
    supersedes_id uuid REFERENCES daos_memory.context_events(id),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    search_document tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', coalesce(title,'') || ' ' || coalesce(summary,'') || ' ' || coalesce(content,''))
    ) STORED
);

CREATE TABLE daos_memory.context_relations (
    from_event_id uuid NOT NULL REFERENCES daos_memory.context_events(id),
    to_event_id uuid NOT NULL REFERENCES daos_memory.context_events(id),
    relation_type text NOT NULL CHECK (relation_type IN ('SUPERSEDES','SUPPORTS','CONTRADICTS','RELATES_TO')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (from_event_id, to_event_id, relation_type),
    CHECK (from_event_id <> to_event_id)
);

CREATE INDEX context_events_current_idx ON daos_memory.context_events (product, topic, created_at DESC) WHERE status='CURRENT';
CREATE INDEX context_events_history_idx ON daos_memory.context_events (product, topic, created_at DESC) WHERE status<>'CURRENT';
CREATE INDEX context_events_search_idx ON daos_memory.context_events USING gin (search_document);
CREATE INDEX canonical_policies_active_idx ON daos_memory.canonical_policies (category, priority DESC) WHERE status='ACTIVE';

INSERT INTO daos_memory.agent_registry (agent_id, role_categories, allowed_memory_types) VALUES
('zeus', ARRAY['STRATEGY'], ARRAY['STRATEGY','ASSESSMENT','SESSION_SUMMARY']),
('athena', ARRAY['RESEARCH'], ARRAY['RESEARCH','ARCHITECTURE_ASSESSMENT','DESIGN_PROPOSAL','ASSESSMENT','SESSION_SUMMARY']),
('hermes', ARRAY['EXECUTION'], ARRAY['EXECUTION','INTEGRATION','OPERATIONAL_STATE','ASSESSMENT','NEXT_ACTION','SESSION_SUMMARY']),
('heracles', ARRAY['DEVELOPMENT'], ARRAY['IMPLEMENTATION','EVIDENCE','TECHNICAL_RESULT','ASSESSMENT','SESSION_SUMMARY']),
('nyx', ARRAY['DEVELOPMENT'], ARRAY['ANALYSIS','IDE_TECHNICAL_RESULT','ASSESSMENT','SESSION_SUMMARY']);

COMMIT;
