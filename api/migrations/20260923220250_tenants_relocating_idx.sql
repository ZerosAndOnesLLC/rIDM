-- no-transaction
-- Every node asks which tenants are being moved every 30 seconds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS tenants_relocating_idx ON tenants (id) WHERE relocating;
