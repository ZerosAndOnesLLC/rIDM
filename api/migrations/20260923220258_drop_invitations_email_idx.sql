-- no-transaction
-- No query reads invitations by e-mail.
DROP INDEX CONCURRENTLY IF EXISTS invitations_email_idx;
