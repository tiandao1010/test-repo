-- The Good Entity — memory schema (PostgreSQL + pgvector).
-- Embedding dim 1536 matches OpenAI's text-embedding-3-small.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS memory_records (
    id            BIGSERIAL PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN (
                      'threat',
                      'incident',
                      'pattern',
                      'reflection',
                      'oracle_intel'
                  )),
    subject       TEXT NOT NULL,                 -- contract addr, tx hash, CVE id, etc.
    summary       TEXT NOT NULL,                 -- short, retrievable
    body          TEXT NOT NULL,                 -- full record (verdict, reasoning, intel...)
    metadata      JSONB NOT NULL DEFAULT '{}',
    embedding     vector(1536) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memory_records_kind_idx
    ON memory_records (kind);

CREATE INDEX IF NOT EXISTS memory_records_subject_idx
    ON memory_records (subject);

-- IVFFLAT index for cosine similarity. Tune `lists` once we have ~10k rows.
CREATE INDEX IF NOT EXISTS memory_records_embedding_idx
    ON memory_records USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
