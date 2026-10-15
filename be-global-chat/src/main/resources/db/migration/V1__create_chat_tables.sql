CREATE TABLE app_users
(
    id            UUID PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE chat_messages
(
    id         UUID PRIMARY KEY,
    author_id  UUID          NOT NULL REFERENCES app_users (id),
    content    VARCHAR(2048) NOT NULL,
    created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chat_message_not_blank
        CHECK (length(btrim(content)) > 0)
);

CREATE INDEX idx_chat_messages_created
    ON chat_messages (created_at DESC, id DESC);
