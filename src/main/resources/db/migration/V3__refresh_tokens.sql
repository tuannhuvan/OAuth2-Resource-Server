CREATE TABLE refresh_tokens (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT       NOT NULL,
    token_hash    VARCHAR(64)  NOT NULL UNIQUE,
    family_id     VARCHAR(36)  NOT NULL,
    ip_address    VARCHAR(45),
    user_agent    VARCHAR(255),
    expires_at    DATETIME(6)  NOT NULL,
    revoked_at    DATETIME(6)  NULL,
    created_at    DATETIME(6)  NOT NULL,
    CONSTRAINT fk_rt_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE revoked_tokens (
    jti        VARCHAR(36) PRIMARY KEY,
    expires_at DATETIME(6) NOT NULL
);
