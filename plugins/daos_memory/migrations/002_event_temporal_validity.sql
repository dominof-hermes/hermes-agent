BEGIN;

LOCK TABLE daos_memory.context_events IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE daos_memory.context_events
    ADD COLUMN IF NOT EXISTS occurred_at timestamptz,
    ADD COLUMN IF NOT EXISTS effective_from timestamptz,
    ADD COLUMN IF NOT EXISTS effective_to timestamptz,
    ADD COLUMN IF NOT EXISTS source_session_at timestamptz;

-- Preserve the pre-migration meaning for existing rows without rewriting
-- created_at, which remains the immutable Production INSERT timestamp.
UPDATE daos_memory.context_events
SET occurred_at = created_at
WHERE occurred_at IS NULL;

UPDATE daos_memory.context_events
SET effective_from = created_at
WHERE effective_from IS NULL;

UPDATE daos_memory.context_events
SET source_session_at = created_at
WHERE source_session_at IS NULL;

ALTER TABLE daos_memory.context_events
    ALTER COLUMN occurred_at SET DEFAULT now(),
    ALTER COLUMN occurred_at SET NOT NULL,
    ALTER COLUMN effective_from SET DEFAULT now(),
    ALTER COLUMN effective_from SET NOT NULL,
    ALTER COLUMN source_session_at SET DEFAULT now(),
    ALTER COLUMN source_session_at SET NOT NULL;

ALTER TABLE daos_memory.context_events
    DROP CONSTRAINT IF EXISTS context_events_status_check;
ALTER TABLE daos_memory.context_events
    ADD CONSTRAINT context_events_status_check
    CHECK (status IN ('CURRENT','SUPERSEDED','HISTORY','CLOSED','DRAFT'));

DO $temporal_constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'daos_memory.context_events'::regclass
          AND conname = 'context_events_effective_window_check'
    ) THEN
        ALTER TABLE daos_memory.context_events
            ADD CONSTRAINT context_events_effective_window_check
            CHECK (effective_to IS NULL OR effective_to >= effective_from);
    END IF;
END
$temporal_constraint$;

CREATE INDEX IF NOT EXISTS context_events_effective_current_idx
ON daos_memory.context_events (
    product,
    topic,
    (CASE authority_level
        WHEN 'OWNER_DECISION' THEN 5
        WHEN 'VERIFIED_EVIDENCE' THEN 4
        WHEN 'OPERATIONAL_STATE' THEN 3
        WHEN 'AGENT_ASSESSMENT' THEN 2
        ELSE 1
    END) DESC,
    effective_from DESC,
    occurred_at DESC,
    created_at DESC
)
WHERE status = 'CURRENT';

COMMIT;
