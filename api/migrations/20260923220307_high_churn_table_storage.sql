-- Tables updated all day: leave room on each page so an update that touches
-- no indexed column stays a HOT update on the same page (sessions are touched
-- every minute while in use, users at every sign-in, refresh tokens when
-- spent, queue rows when their status moves), and vacuum and analyze the
-- high-churn tables after 2% of their rows change instead of 20%, so dead
-- rows do not pile up between runs. SET (...) takes SHARE UPDATE EXCLUSIVE:
-- reads and writes go on; the fill factor applies to pages written from now.
ALTER TABLE sso_sessions SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE users SET (fillfactor = 85);
ALTER TABLE refresh_tokens SET (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE outbound_messages SET (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE webhook_deliveries SET (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
ALTER TABLE login_attempts SET (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
