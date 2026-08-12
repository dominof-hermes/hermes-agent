BEGIN;

UPDATE daos_memory.canonical_policies
SET category = 'GLOBAL'
WHERE category = 'GENERAL';

COMMIT;