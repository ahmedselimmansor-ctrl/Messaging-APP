-- Per-service Cassandra roles.
--
-- Until this file existed, every service shared one Cassandra username and
-- password. That meant a compromise of any component that touches Cassandra
-- was a compromise of all of it — the media service could have read message
-- bodies, the search indexer could have deleted history.
--
-- Cassandra's permission model is coarser than Postgres's: it grants on
-- keyspaces and tables, not on columns. So the separation here is by table,
-- which is still a large reduction in blast radius.
--
-- Applied by the schema Job after schema.cql. Passwords come from Secret
-- Manager, one per service, and are substituted at apply time — they are not
-- in this file and must never be.

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
--
-- LOGIN = true and SUPERUSER = false on every one. A superuser role in an
-- application service is the Cassandra equivalent of running as root.

CREATE ROLE IF NOT EXISTS svc_chat
    WITH PASSWORD = ':chat_password' AND LOGIN = true AND SUPERUSER = false;

CREATE ROLE IF NOT EXISTS svc_persister
    WITH PASSWORD = ':persister_password' AND LOGIN = true AND SUPERUSER = false;

CREATE ROLE IF NOT EXISTS svc_media
    WITH PASSWORD = ':media_password' AND LOGIN = true AND SUPERUSER = false;

-- Read-only, for investigation and analytics. Handing an operator the chat
-- service's credentials to answer a support question is how a read turns into
-- an accidental write.
CREATE ROLE IF NOT EXISTS svc_readonly
    WITH PASSWORD = ':readonly_password' AND LOGIN = true AND SUPERUSER = false;

-- ---------------------------------------------------------------------------
-- chat-service: reads history, writes edits and deletes
-- ---------------------------------------------------------------------------
--
-- It does not write new messages. That is the persister's job, downstream of
-- Kafka — so the chat service cannot insert a message that skipped the
-- durability boundary.

GRANT SELECT ON messaging.messages_by_chat TO svc_chat;
GRANT MODIFY ON messaging.messages_by_chat TO svc_chat;  -- edit and soft-delete
GRANT SELECT ON messaging.messages_by_chat_buckets TO svc_chat;
GRANT SELECT ON messaging.message_by_id TO svc_chat;
GRANT SELECT ON messaging.message_dedupe TO svc_chat;
GRANT SELECT, MODIFY ON messaging.message_reactions TO svc_chat;
GRANT SELECT, MODIFY ON messaging.message_edits TO svc_chat;

-- ---------------------------------------------------------------------------
-- persister: the only writer of message history
-- ---------------------------------------------------------------------------

GRANT SELECT, MODIFY ON messaging.messages_by_chat TO svc_persister;
GRANT SELECT, MODIFY ON messaging.messages_by_chat_buckets TO svc_persister;
GRANT SELECT, MODIFY ON messaging.message_by_id TO svc_persister;
GRANT SELECT, MODIFY ON messaging.message_dedupe TO svc_persister;
GRANT SELECT, MODIFY ON messaging.media_acl TO svc_persister;

-- ---------------------------------------------------------------------------
-- media-service: the media ACL, and nothing else
-- ---------------------------------------------------------------------------
--
-- This is the grant that matters most. The media service is reachable from
-- the internet and handles attacker-supplied paths; it needs to answer
-- "which chat owns this object?" and must not be able to read a single
-- message body.

GRANT SELECT ON messaging.media_acl TO svc_media;

-- ---------------------------------------------------------------------------
-- read-only
-- ---------------------------------------------------------------------------

GRANT SELECT ON KEYSPACE messaging TO svc_readonly;

-- ---------------------------------------------------------------------------
-- Lock down the default superuser
-- ---------------------------------------------------------------------------
--
-- Cassandra ships with cassandra/cassandra as a superuser, and it is the
-- first credential anyone tries. The bootstrap changes its password to a
-- generated value held in Secret Manager; this is the reminder that leaving
-- it at the default is equivalent to having no authentication at all.
--
--   ALTER ROLE cassandra WITH PASSWORD = '<from Secret Manager>';
--
-- Authentication and authorisation must both be enabled in cassandra.yaml, or
-- none of the above is enforced:
--
--   authenticator: PasswordAuthenticator
--   authorizer: CassandraAuthorizer
--   role_manager: CassandraRoleManager
--
-- And the system_auth keyspace must be replicated, or losing one node makes
-- every service unable to authenticate:
--
--   ALTER KEYSPACE system_auth WITH replication = {
--     'class': 'NetworkTopologyStrategy', 'europe-west1': 3
--   };
