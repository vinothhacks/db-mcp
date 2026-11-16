-- DB-MCP live SQL Server fixture (mirrors the sample schema of config/db-mcp.example.toml).
-- Run as sa: sqlcmd -C -S localhost -U sa -P <pw> -i 01-schema.sql
SET NOCOUNT ON;
GO
IF DB_ID(N'dbmcp_fixture') IS NOT NULL
BEGIN
    ALTER DATABASE dbmcp_fixture SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE dbmcp_fixture;
END
GO
CREATE DATABASE dbmcp_fixture;
GO
ALTER DATABASE dbmcp_fixture SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE, QUERY_CAPTURE_MODE = ALL);
GO
USE dbmcp_fixture;
GO
CREATE TABLE dbo.users (
    id INT NOT NULL CONSTRAINT pk_users PRIMARY KEY,
    email NVARCHAR(255) NOT NULL,
    role NVARCHAR(50) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    created_at DATETIME2(3) NOT NULL CONSTRAINT df_users_created DEFAULT SYSUTCDATETIME()
);
CREATE TABLE dbo.orders (
    id INT NOT NULL CONSTRAINT pk_orders PRIMARY KEY,
    user_id INT NOT NULL CONSTRAINT fk_orders_users REFERENCES dbo.users(id) ON DELETE CASCADE,
    status NVARCHAR(20) NOT NULL,
    total_cents INT NOT NULL,
    created_at DATETIME2(3) NOT NULL
);
CREATE TABLE dbo.inventory (
    sku NVARCHAR(32) NOT NULL CONSTRAINT pk_inventory PRIMARY KEY,
    available_qty INT NOT NULL,
    reserved_qty INT NOT NULL CONSTRAINT df_inventory_reserved DEFAULT 0
);
CREATE TABLE dbo.order_items (
    id INT NOT NULL CONSTRAINT pk_order_items PRIMARY KEY,
    order_id INT NOT NULL CONSTRAINT fk_items_orders REFERENCES dbo.orders(id) ON DELETE CASCADE,
    sku NVARCHAR(32) NOT NULL CONSTRAINT fk_items_inventory REFERENCES dbo.inventory(sku),
    quantity INT NOT NULL,
    unit_price_cents INT NOT NULL
);
CREATE TABLE dbo.audit_logs (
    id INT IDENTITY(1,1) NOT NULL CONSTRAINT pk_audit_logs PRIMARY KEY,
    order_id INT NOT NULL CONSTRAINT fk_audit_orders REFERENCES dbo.orders(id) ON DELETE CASCADE,
    event_type NVARCHAR(64) NOT NULL,
    created_at DATETIME2(3) NOT NULL
);
CREATE TABLE dbo.internal_secrets (
    id INT NOT NULL CONSTRAINT pk_internal_secrets PRIMARY KEY,
    secret_key NVARCHAR(100) NOT NULL,
    secret_value NVARCHAR(400) NOT NULL
);
-- Heap without a primary key plus a duplicate index: exercised by database_health.
CREATE TABLE dbo.event_staging (
    event_id BIGINT NOT NULL,
    payload NVARCHAR(400) NULL,
    amount DECIMAL(12,2) NULL,
    ref_guid UNIQUEIDENTIFIER NULL,
    raw_bytes VARBINARY(16) NULL,
    happened_at DATETIMEOFFSET(0) NULL,
    is_valid BIT NULL
);
CREATE INDEX ix_staging_event ON dbo.event_staging(event_id);
CREATE INDEX ix_staging_event_dup ON dbo.event_staging(event_id);
EXEC sys.sp_addextendedproperty @name = N'MS_Description', @value = N'Customer accounts',
    @level0type = N'SCHEMA', @level0name = N'dbo', @level1type = N'TABLE', @level1name = N'users';
GO
CREATE VIEW dbo.active_user_orders AS
    SELECT o.id AS order_id, u.id AS user_id, u.email, o.status, o.total_cents, o.created_at
    FROM dbo.orders o
    JOIN dbo.users u ON o.user_id = u.id
    WHERE o.status = 'completed';
GO
CREATE PROCEDURE dbo.record_order_audit @order_id INT, @event_type NVARCHAR(64) AS
BEGIN
    INSERT INTO dbo.audit_logs (order_id, event_type, created_at)
    SELECT o.id, @event_type, o.created_at FROM dbo.orders o WHERE o.id = @order_id;
END
GO
CREATE PROCEDURE dbo.reserve_inventory @order_id INT AS
BEGIN
    UPDATE dbo.inventory SET reserved_qty = reserved_qty + 1
    WHERE sku IN (SELECT oi.sku FROM dbo.order_items oi WHERE oi.order_id = @order_id);
    EXEC dbo.record_order_audit @order_id, N'INVENTORY_RESERVED';
END
GO
CREATE FUNCTION dbo.calculate_order_discount (@order_id INT) RETURNS DECIMAL(12,2) AS
BEGIN
    RETURN (SELECT o.total_cents * 0.10 FROM dbo.orders o JOIN dbo.users u ON u.id = o.user_id WHERE o.id = @order_id);
END
GO
CREATE PROCEDURE dbo.checkout_order @order_id INT AS
BEGIN
    DECLARE @discount DECIMAL(12,2) = dbo.calculate_order_discount(@order_id);
    UPDATE dbo.orders SET status = 'completed'
    WHERE id = @order_id AND user_id IN (SELECT u.id FROM dbo.users u WHERE u.role = 'customer');
    EXEC dbo.reserve_inventory @order_id;
    EXEC dbo.record_order_audit @order_id, N'ORDER_CHECKED_OUT';
END
GO
CREATE TRIGGER dbo.trg_orders_audit ON dbo.orders AFTER UPDATE AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.audit_logs (order_id, event_type, created_at)
    SELECT i.id, N'ORDER_UPDATED', SYSUTCDATETIME() FROM inserted i;
END
GO
INSERT INTO dbo.users (id, email, role, password_hash, created_at) VALUES
    (1, 'alice@example.com', 'admin', 'hash_alice_secret', '2025-01-01T00:00:00'),
    (2, 'bob@example.com', 'customer', 'hash_bob_secret', '2025-01-02T00:00:00'),
    (3, 'carol@example.com', 'customer', 'hash_carol_secret', '2025-01-05T00:00:00');
INSERT INTO dbo.orders (id, user_id, status, total_cents, created_at) VALUES
    (101, 1, 'completed', 4500, '2025-01-03T10:00:00'),
    (102, 2, 'pending', 1900, '2025-01-04T12:00:00'),
    (103, 3, 'completed', 2500, '2025-01-06T09:30:00'),
    (104, 2, 'completed', 1200, '2025-01-07T15:45:00');
INSERT INTO dbo.inventory (sku, available_qty, reserved_qty) VALUES
    ('SKU-PRO-1', 50, 1), ('SKU-STD-2', 100, 0);
INSERT INTO dbo.order_items (id, order_id, sku, quantity, unit_price_cents) VALUES
    (1001, 101, 'SKU-PRO-1', 1, 4500), (1002, 102, 'SKU-STD-2', 1, 1900),
    (1003, 103, 'SKU-STD-2', 2, 1250), (1004, 104, 'SKU-STD-2', 1, 1200);
INSERT INTO dbo.audit_logs (order_id, event_type, created_at) VALUES
    (101, 'ORDER_CHECKED_OUT', '2025-01-03T10:01:00');
INSERT INTO dbo.internal_secrets (id, secret_key, secret_value) VALUES (1, 'api', 'do-not-leak');
INSERT INTO dbo.event_staging VALUES
    (1, N'first', 12.50, '6F9619FF-8B86-D011-B42D-00C04FC964FF', 0xDEAD01, '2025-05-06T07:08:09+02:00', 1),
    (2, NULL, NULL, NULL, NULL, NULL, NULL);
GO
