//! End-to-End Integration Suite index covering stdio, Streamable HTTP, and out-of-band CLI approval.
//! Rust tests live in `crates/db-mcp-server/tests/contracts_and_security.rs` and Node E2E tests in `npm/test/e2e.test.js`.

pub const DEPLOYMENT_MODES_TESTED: [&str; 3] = [
    "verify-config",
    "stdio-mcp-with-cli-approval",
    "streamable-http-with-bearer-and-admin-approval",
];
