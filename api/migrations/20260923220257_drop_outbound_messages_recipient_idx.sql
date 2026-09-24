-- no-transaction
-- No query reads messages by recipient.
DROP INDEX CONCURRENTLY IF EXISTS outbound_messages_recipient_idx;
