-- DB-MCP live MySQL 8 fixture: mirrors the bundled sample schema (config/db-mcp.example.toml)
-- plus a few objects that exercise value mapping, timeouts and health findings.
-- Loaded as root by scripts/live-db-up.sh mysql; the server under test only ever uses the
-- read-only accounts created in 02-users.sql.tmpl.
CREATE DATABASE IF NOT EXISTS appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE appdb;

CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB COMMENT='Application users';

CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL,
    total_cents BIGINT NOT NULL,
    created_at DATETIME NOT NULL,
    CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB COMMENT='Customer orders';

CREATE TABLE inventory (
    sku VARCHAR(64) PRIMARY KEY,
    available_qty INT NOT NULL,
    reserved_qty INT NOT NULL DEFAULT 0
) ENGINE=InnoDB;

CREATE TABLE order_items (
    id BIGINT PRIMARY KEY,
    order_id BIGINT NOT NULL,
    sku VARCHAR(64) NOT NULL,
    quantity INT NOT NULL,
    unit_price_cents BIGINT NOT NULL,
    CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
    CONSTRAINT fk_order_items_sku FOREIGN KEY (sku) REFERENCES inventory (sku)
) ENGINE=InnoDB;

CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    CONSTRAINT fk_audit_logs_order FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE internal_secrets (
    id BIGINT PRIMARY KEY,
    secret_key VARCHAR(128) NOT NULL,
    secret_value VARCHAR(255) NOT NULL
) ENGINE=InnoDB;

-- Value-mapping fixture: one row per interesting MySQL type.
CREATE TABLE type_samples (
    id INT PRIMARY KEY,
    i_tiny TINYINT,
    i_big_u BIGINT UNSIGNED,
    d_dec DECIMAL(20, 6),
    f_double DOUBLE,
    dt DATETIME(3),
    d DATE,
    t TIME,
    y YEAR,
    b_bin VARBINARY(16),
    j JSON,
    e ENUM('small', 'large'),
    bits BIT(8),
    txt TEXT,
    n_null VARCHAR(10) NULL
) ENGINE=InnoDB;

-- Health fixtures: a table without a primary key and a redundant (prefix) index.
CREATE TABLE event_log_nopk (
    event_time DATETIME NOT NULL,
    message VARCHAR(255)
) ENGINE=InnoDB;
CREATE INDEX idx_orders_status ON orders (status);
CREATE INDEX idx_orders_status_created ON orders (status, created_at);

-- 1000 rows used for slow cross joins (timeout tests).
CREATE TABLE numbers (n INT PRIMARY KEY) ENGINE=InnoDB;

CREATE VIEW active_user_orders AS
    SELECT o.id AS order_id, u.id AS user_id, u.email, o.status, o.total_cents, o.created_at
    FROM orders o
    JOIN users u ON o.user_id = u.id
    WHERE o.status = 'completed';

INSERT INTO users (id, email, role, password_hash, created_at) VALUES
    (1, 'alice@example.com', 'admin', 'hash_alice_secret', '2025-01-01 00:00:00'),
    (2, 'bob@example.com', 'customer', 'hash_bob_secret', '2025-01-02 00:00:00');
INSERT INTO orders (id, user_id, status, total_cents, created_at) VALUES
    (101, 1, 'completed', 4500, '2025-01-03 10:00:00'),
    (102, 2, 'pending', 1900, '2025-01-04 12:00:00');
INSERT INTO inventory (sku, available_qty, reserved_qty) VALUES
    ('SKU-PRO-1', 50, 1),
    ('SKU-STD-2', 100, 0);
INSERT INTO order_items (id, order_id, sku, quantity, unit_price_cents) VALUES
    (1001, 101, 'SKU-PRO-1', 1, 4500),
    (1002, 102, 'SKU-STD-2', 1, 1900);
INSERT INTO audit_logs (id, order_id, event_type, created_at) VALUES
    (1, 101, 'ORDER_CHECKED_OUT', '2025-01-03 10:01:00');
INSERT INTO internal_secrets (id, secret_key, secret_value) VALUES
    (1, 'stripe', 'sk_live_do_not_leak');
INSERT INTO type_samples VALUES
    (1, -7, 18446744073709551615, 12345.678900, 3.5, '2025-01-03 10:00:00.123', '2025-01-03', '13:14:15', 2025,
     UNHEX('DEADBEEF'), '{"k": [1, 2]}', 'large', b'10100101', 'héllo 日本', NULL);
INSERT INTO event_log_nopk VALUES ('2025-01-03 10:00:00', 'boot');
INSERT INTO numbers (n)
    WITH RECURSIVE seq (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 1000)
    SELECT n FROM seq;

DELIMITER //
CREATE PROCEDURE record_order_audit(IN p_order_id BIGINT, IN p_event_type VARCHAR(64))
BEGIN
    INSERT INTO audit_logs (order_id, event_type, created_at)
    SELECT o.id, p_event_type, o.created_at
    FROM orders o
    WHERE o.id = p_order_id;
END //
CREATE PROCEDURE reserve_inventory(IN p_order_id BIGINT)
BEGIN
    UPDATE inventory
    SET reserved_qty = reserved_qty + 1
    WHERE sku IN (SELECT oi.sku FROM order_items oi WHERE oi.order_id = p_order_id);
    CALL record_order_audit(p_order_id, 'INVENTORY_RESERVED');
END //
CREATE FUNCTION calculate_order_discount(p_order_id BIGINT)
RETURNS DECIMAL(12, 2)
READS SQL DATA
BEGIN
    RETURN (SELECT o.total_cents * 0.10 FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = p_order_id);
END //
CREATE PROCEDURE checkout_order(IN p_order_id BIGINT)
BEGIN
    SELECT calculate_order_discount(p_order_id);
    UPDATE orders SET status = 'completed'
    WHERE id = p_order_id AND user_id IN (SELECT u.id FROM users u WHERE u.role = 'customer');
    CALL reserve_inventory(p_order_id);
    CALL record_order_audit(p_order_id, 'ORDER_CHECKED_OUT');
END //
CREATE TRIGGER trg_orders_status_audit AFTER UPDATE ON orders
FOR EACH ROW
BEGIN
    IF NEW.status <> OLD.status THEN
        INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (NEW.id, 'STATUS_CHANGED', NOW());
    END IF;
END //
DELIMITER ;

ANALYZE TABLE users, orders, inventory, order_items, audit_logs, numbers;
