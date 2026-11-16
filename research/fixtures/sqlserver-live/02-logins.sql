-- Read-only logins for the DB-MCP SQL Server fixture. sqlcmd variables:
--   RO_PASSWORD   password of dbmcp_ro       (db_datareader only: degraded diagnostics)
--   FULL_PASSWORD password of dbmcp_ro_full  (db_datareader + VIEW DEFINITION, SHOWPLAN,
--                                             VIEW DATABASE STATE, VIEW SERVER STATE)
SET NOCOUNT ON;
GO
USE master;
GO
IF SUSER_ID(N'dbmcp_ro') IS NOT NULL DROP LOGIN dbmcp_ro;
IF SUSER_ID(N'dbmcp_ro_full') IS NOT NULL DROP LOGIN dbmcp_ro_full;
GO
CREATE LOGIN dbmcp_ro WITH PASSWORD = N'$(RO_PASSWORD)', DEFAULT_DATABASE = dbmcp_fixture, CHECK_POLICY = OFF;
CREATE LOGIN dbmcp_ro_full WITH PASSWORD = N'$(FULL_PASSWORD)', DEFAULT_DATABASE = master, CHECK_POLICY = OFF;
GRANT VIEW SERVER STATE TO dbmcp_ro_full;
GO
USE dbmcp_fixture;
GO
CREATE USER dbmcp_ro FOR LOGIN dbmcp_ro;
CREATE USER dbmcp_ro_full FOR LOGIN dbmcp_ro_full;
ALTER ROLE db_datareader ADD MEMBER dbmcp_ro;
ALTER ROLE db_datareader ADD MEMBER dbmcp_ro_full;
GRANT VIEW DEFINITION TO dbmcp_ro_full;
GRANT SHOWPLAN TO dbmcp_ro_full;
GRANT VIEW DATABASE STATE TO dbmcp_ro_full;
GO
