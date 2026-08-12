BEGIN;

CREATE TABLE daos_memory.knowledge_sources (
    id uuid PRIMARY KEY,
    source_type text NOT NULL CHECK (source_type IN (
        'CHAT_CONVERSATION','SLACK_THREAD','GIT_MD','ARCHITECTURE','ADR','RUNBOOK',
        'INCIDENT','EVIDENCE','ATTACHMENT','ENGINEERING_NOTE'
    )),
    title varchar(240) NOT NULL,
    source_interface varchar(80) NOT NULL,
    actor varchar(80) NOT NULL,
    participants text[] NOT NULL DEFAULT '{}',
    repository varchar(240),
    path varchar(1000),
    commit_sha varchar(64),
    source_url varchar(1000),
    occurred_at timestamptz NOT NULL,
    source_session_at timestamptz NOT NULL,
    indexed_at timestamptz NOT NULL DEFAULT now(),
    content text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 524288),
    content_hash char(64) NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    access_scope text NOT NULL CHECK (access_scope IN ('OWNER','COMPANY','PRODUCT','RESTRICTED')),
    security_level text NOT NULL CHECK (security_level IN ('INTERNAL','RESTRICTED')),
    redaction_status text NOT NULL CHECK (redaction_status='REVIEWED_NO_SECRETS'),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (cardinality(participants) <= 32),
    CHECK (
        source_type NOT IN ('GIT_MD','ARCHITECTURE','ADR','RUNBOOK','ENGINEERING_NOTE')
        OR (repository IS NOT NULL AND path IS NOT NULL AND commit_sha ~ '^[0-9a-f]{40,64}$')
    )
);

CREATE UNIQUE INDEX knowledge_sources_content_location_uidx
ON daos_memory.knowledge_sources (
    source_type, content_hash, coalesce(repository,''), coalesce(path,''), coalesce(commit_sha,'')
);
CREATE INDEX knowledge_sources_time_idx
ON daos_memory.knowledge_sources (occurred_at DESC, indexed_at DESC);

CREATE TABLE daos_memory.knowledge_relations (
    id uuid PRIMARY KEY,
    from_event_id uuid REFERENCES daos_memory.context_events(id),
    from_source_id uuid REFERENCES daos_memory.knowledge_sources(id),
    to_event_id uuid REFERENCES daos_memory.context_events(id),
    to_source_id uuid REFERENCES daos_memory.knowledge_sources(id),
    relation_type text NOT NULL CHECK (relation_type IN (
        'SUMMARIZES','DERIVED_FROM','SOURCE_OF','RELATED_TO','SUPERSEDES',
        'EVIDENCE_FOR','DECIDED_BY','IMPLEMENTED_BY'
    )),
    created_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK ((from_event_id IS NOT NULL)::int + (from_source_id IS NOT NULL)::int = 1),
    CHECK ((to_event_id IS NOT NULL)::int + (to_source_id IS NOT NULL)::int = 1),
    CHECK (from_event_id IS NULL OR to_event_id IS NULL OR from_event_id <> to_event_id),
    CHECK (from_source_id IS NULL OR to_source_id IS NULL OR from_source_id <> to_source_id)
);

CREATE UNIQUE INDEX knowledge_relations_edge_uidx
ON daos_memory.knowledge_relations (
    coalesce(from_event_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(from_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(to_event_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(to_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
    relation_type
);
CREATE INDEX knowledge_relations_from_event_idx ON daos_memory.knowledge_relations (from_event_id) WHERE from_event_id IS NOT NULL;
CREATE INDEX knowledge_relations_to_event_idx ON daos_memory.knowledge_relations (to_event_id) WHERE to_event_id IS NOT NULL;
CREATE INDEX knowledge_relations_from_source_idx ON daos_memory.knowledge_relations (from_source_id) WHERE from_source_id IS NOT NULL;
CREATE INDEX knowledge_relations_to_source_idx ON daos_memory.knowledge_relations (to_source_id) WHERE to_source_id IS NOT NULL;

DO $grant_runtime$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daos_memory_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT ON daos_memory.knowledge_sources, daos_memory.knowledge_relations TO daos_memory_runtime';
    END IF;
END
$grant_runtime$;

COMMIT;
