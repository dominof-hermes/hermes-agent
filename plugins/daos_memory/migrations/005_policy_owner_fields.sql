BEGIN;

ALTER TABLE daos_memory.canonical_policies
    ADD COLUMN IF NOT EXISTS author varchar(80) NOT NULL DEFAULT 'Owner';

COMMIT;