-- 0003: support the contact-import query and the blocklist send-path check.

BEGIN;

-- Contact import hashes the stored phone number in SQL rather than keeping a
-- denormalised hash column. That choice means rotating the pepper is a config
-- change with no migration — but it also means the hash cannot be indexed,
-- so the query is a sequential scan over the users table.
--
-- pgcrypto provides hmac(). It is in the default Cloud SQL extension list.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The blocklist check runs on the send path of every private message, so both
-- directions of the symmetric lookup must be indexed. The primary key covers
-- (owner_id, blocked_id); this covers the reverse.
CREATE INDEX IF NOT EXISTS blocklist_pair_reverse_idx
    ON blocklist (blocked_id, owner_id);

-- "Who has me in their contacts?" drives presence visibility.
CREATE INDEX IF NOT EXISTS contacts_user_owner_idx
    ON contacts (user_id, owner_id);

-- Contact list ordering.
CREATE INDEX IF NOT EXISTS contacts_owner_name_idx
    ON contacts (owner_id, first_name, last_name);

COMMIT;
