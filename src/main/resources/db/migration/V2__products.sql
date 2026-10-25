CREATE TABLE products (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(120)   NOT NULL,
    description VARCHAR(500),
    price       DECIMAL(12, 2) NOT NULL,
    created_at  DATETIME(6),
    updated_at  DATETIME(6)
);
