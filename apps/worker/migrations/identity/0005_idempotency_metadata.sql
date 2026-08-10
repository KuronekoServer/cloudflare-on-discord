ALTER TABLE idempotency_keys ADD COLUMN request_hash TEXT;
ALTER TABLE idempotency_keys ADD COLUMN response_status INTEGER;
ALTER TABLE idempotency_keys ADD COLUMN response_headers TEXT;
