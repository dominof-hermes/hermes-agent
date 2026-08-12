BEGIN;

-- Owner approved replacing legacy Memory content. Agent credentials remain intact.
TRUNCATE TABLE daos_memory.knowledge_relations, daos_memory.knowledge_sources,
    daos_memory.context_relations, daos_memory.context_events, daos_memory.canonical_policies CASCADE;

CREATE TABLE daos_memory.current_contexts (
    id uuid PRIMARY KEY,
    product varchar(120) NOT NULL,
    topic varchar(160) NOT NULL,
    title varchar(240) NOT NULL,
    summary varchar(1200) NOT NULL,
    next_action varchar(1200) NOT NULL,
    actor varchar(80) NOT NULL REFERENCES daos_memory.agent_registry(agent_id),
    occurred_at timestamptz NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'CURRENT' CHECK (status IN ('CURRENT','SUPERSEDED','CLOSED','HISTORICAL')),
    related_note_ids uuid[] NOT NULL DEFAULT '{}',
    related_decision_ids uuid[] NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX current_contexts_one_current_idx
    ON daos_memory.current_contexts(product, topic) WHERE status='CURRENT';

CREATE TABLE daos_memory.decisions (
    id uuid PRIMARY KEY,
    product varchar(120) NOT NULL,
    topic varchar(160) NOT NULL,
    title varchar(240) NOT NULL,
    decision_content varchar(8000) NOT NULL,
    proposed_by varchar(80) NOT NULL REFERENCES daos_memory.agent_registry(agent_id),
    occurred_at timestamptz NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'PENDING_OWNER_CONFIRM' CHECK (status IN ('PENDING_OWNER_CONFIRM','APPROVED','REJECTED','SUPERSEDED')),
    authority_level text NOT NULL DEFAULT 'AGENT_ASSESSMENT' CHECK (authority_level IN ('AGENT_ASSESSMENT','OWNER_DECISION')),
    owner_comment varchar(1200),
    approved_at timestamptz,
    supersedes_id uuid REFERENCES daos_memory.decisions(id),
    related_note_ids uuid[] NOT NULL DEFAULT '{}',
    related_source_ids uuid[] NOT NULL DEFAULT '{}'
);

DROP TABLE daos_memory.canonical_policies;
CREATE TABLE daos_memory.canonical_policies (
    id uuid PRIMARY KEY,
    category varchar(80) NOT NULL,
    title varchar(240) NOT NULL,
    content varchar(8000) NOT NULL,
    scope varchar(160) NOT NULL,
    status text NOT NULL CHECK (status IN ('DRAFT','ACTIVE','SUPERSEDED')),
    version integer NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE daos_memory.agent_notes (
    id uuid PRIMARY KEY,
    actor varchar(80) NOT NULL REFERENCES daos_memory.agent_registry(agent_id),
    actor_role varchar(80) NOT NULL,
    product varchar(120) NOT NULL,
    topic varchar(160) NOT NULL,
    note_type text NOT NULL CHECK (note_type IN ('STRATEGY','ASSESSMENT','ARCHITECTURE','ENGINEERING_KNOWLEDGE','EXECUTION_REPORT','RESEARCH','MARKET_INTELLIGENCE','IMPLEMENTATION_NOTE','INCIDENT_LEARNING')),
    title varchar(240) NOT NULL,
    summary varchar(1200) NOT NULL,
    full_content varchar(16000) NOT NULL,
    occurred_at timestamptz NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status IN ('CURRENT','CLOSED','HISTORICAL','SUPERSEDED')),
    related_source_ids uuid[] NOT NULL DEFAULT '{}',
    related_note_ids uuid[] NOT NULL DEFAULT '{}',
    access_scope text NOT NULL CHECK (access_scope IN ('OWNER','COMPANY','PRODUCT','RESTRICTED')),
    security_level text NOT NULL CHECK (security_level IN ('INTERNAL','RESTRICTED'))
);

ALTER TABLE daos_memory.knowledge_sources
    ADD COLUMN IF NOT EXISTS product varchar(120),
    ADD COLUMN IF NOT EXISTS topic varchar(160),
    ADD COLUMN IF NOT EXISTS file_reference varchar(1000),
    ADD COLUMN IF NOT EXISTS imported_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE daos_memory.knowledge_sources
    DROP CONSTRAINT IF EXISTS knowledge_sources_source_type_check;
ALTER TABLE daos_memory.knowledge_sources
    ADD CONSTRAINT knowledge_sources_source_type_check CHECK (source_type IN (
      'CHAT_CONVERSATION','SLACK_THREAD','GIT_MD','PDF','ARCHITECTURE_DOCUMENT',
      'RUNBOOK','ADR','EVIDENCE','ATTACHMENT','ENGINEERING_DOCUMENT'
    ));

DO $grant_runtime$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='daos_memory_runtime') THEN
    EXECUTE 'GRANT SELECT, INSERT ON daos_memory.current_contexts, daos_memory.decisions, daos_memory.agent_notes TO daos_memory_runtime';
    EXECUTE 'GRANT UPDATE (status) ON daos_memory.current_contexts TO daos_memory_runtime';
    EXECUTE 'GRANT SELECT ON daos_memory.canonical_policies TO daos_memory_runtime';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON daos_memory.decisions, daos_memory.canonical_policies TO daos_memory_runtime';
  END IF;
END
$grant_runtime$;

COMMIT;
