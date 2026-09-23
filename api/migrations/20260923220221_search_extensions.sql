-- Trigram indexes for the `ILIKE` searches of the organization, client and
-- tenant lists (`pg_trgm`), and `btree_gin` so those GIN indexes can lead
-- with `tenant_id` like every other tenant-scoped index. Both are trusted
-- extensions: the migrator creates them without being a superuser.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
