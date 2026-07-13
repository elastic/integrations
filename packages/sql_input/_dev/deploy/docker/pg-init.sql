-- Seed an append-only table used by the cursor-mode system test (PostgreSQL).
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  payload VARCHAR(255) NOT NULL
);

INSERT INTO audit_log (event_type, payload) VALUES
  ('login',  'user=alice'),
  ('logout', 'user=alice'),
  ('login',  'user=bob'),
  ('update', 'record=42'),
  ('delete', 'record=7');
