-- When each audit chain's oldest remaining row was written, so the daily
-- retention pass visits only the chains that hold something past their
-- retention instead of probing every chain's rows. The writer sets it when
-- a chain starts, the purge after it removes rows; 'infinity' marks a chain
-- whose rows are all gone, and NULL one not looked at yet (the next
-- retention pass looks, once).
ALTER TABLE audit_chains ADD COLUMN oldest_at timestamptz;
