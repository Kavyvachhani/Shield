//! The SentinelVAPT MCP server, over stdio.
//!
//! Register it with any MCP client. For Claude Code:
//!
//! ```text
//! claude mcp add sentinelvapt -- /path/to/sentinel-mcp
//! ```
//!
//! Or in a client's configuration file:
//!
//! ```json
//! { "mcpServers": { "sentinelvapt": { "command": "/path/to/sentinel-mcp" } } }
//! ```
//!
//! Everything the server can do is described by `tools/list`; the static tools
//! read local files and the one dynamic tool refuses to send a request without
//! a signed authorisation.
//!
//! Diagnostics go to stderr. stdout carries the protocol and nothing else — a
//! stray `println!` there desynchronises the client, which is why this binary
//! writes no banner.

use sentinel_mcp::MCPServer;
use tokio::io::{stdin, stdout, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!(
        "SentinelVAPT MCP server {} — protocol {}. Reading JSON-RPC from stdin.",
        env!("CARGO_PKG_VERSION"),
        sentinel_mcp::PROTOCOL_VERSION
    );

    MCPServer::serve(BufReader::new(stdin()), stdout()).await?;
    Ok(())
}
