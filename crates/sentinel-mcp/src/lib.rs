//! A Model Context Protocol server over SentinelVAPT's engines.
//!
//! The desktop application is where an analyst runs an assessment. This is the
//! other way in: an agent, an editor or a CI job speaks MCP over stdio and gets
//! the same engines, the same finding model and — critically — the same safety
//! gate. One integration point rather than a dozen scanner CLIs, each with its
//! own output dialect.
//!
//! WHAT IS AND IS NOT EXPOSED
//! ──────────────────────────
//! The static engines are exposed freely. They read files on the machine the
//! server is already running on, execute nothing they find, and reach no
//! network except the advisory database. There is nothing an agent can do with
//! them that it could not do by reading the files itself.
//!
//! Everything that sends a request to a target is exposed **only through the
//! authorisation gate**, and the gate is checked here as well as inside the
//! adapter. That redundancy is deliberate: this server's whole purpose is to
//! let something non-human decide what to scan, and "the model asked me to" is
//! not authorisation to send traffic to somebody's production system. A caller
//! that wants dynamic testing has to supply a signed Rules of Engagement
//! record, and the server refuses without one — no flag, no environment
//! variable, no parameter turns that off.
//!
//! PROTOCOL
//! ────────
//! JSON-RPC 2.0 over stdio, one message per line. `initialize`, `tools/list`
//! and `tools/call` are implemented; `notifications/*` are accepted and
//! acknowledged. A request with no `id` is a notification and gets no reply, as
//! the specification requires — replying to one is the most common way an MCP
//! server desynchronises its client.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod tools;

/// The protocol revision this server implements.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPRequest {
    pub jsonrpc: String,
    /// Absent for a notification, which must not be answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl MCPResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(json!({ "code": code, "message": message.into() })),
        }
    }
}

/// JSON-RPC error codes, plus the one this server adds.
pub mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    /// The caller asked for something that would send traffic to a target
    /// without a signed authorisation. Distinct from `INVALID_PARAMS` so a
    /// client can tell "you gave me bad input" from "I will not do that".
    pub const NOT_AUTHORIZED: i32 = -32001;
}

pub struct MCPServer;

impl MCPServer {
    /// Handle one request. Returns `None` for a notification.
    pub async fn handle(req: MCPRequest) -> Option<MCPResponse> {
        // A notification has no id and, per the specification, no reply. A
        // server that answers one leaves an extra message in the stream and
        // every subsequent correlation is off by one.
        let is_notification = req.id.is_none();
        if is_notification && !req.method.starts_with("notifications/") {
            return None;
        }

        let response = match req.method.as_str() {
            "initialize" => MCPResponse::ok(
                req.id.clone(),
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "sentinelvapt",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions":
                        "SentinelVAPT's assessment engines. The static tools — analyse_code, \
                         audit_dependencies, find_secrets, audit_infrastructure — read local \
                         files and are safe to call on any checkout. assess_target sends HTTP \
                         requests to a live system and is refused unless a signed Rules of \
                         Engagement record is supplied; that is not a configurable behaviour. \
                         Findings come back in one normalised model with CVSS 4.0 scoring, \
                         CWE/OWASP/WSTG mapping, and an explicit statement of what each \
                         finding's evidence does and does not establish.",
                }),
            ),
            "ping" => MCPResponse::ok(req.id.clone(), json!({})),
            "tools/list" => MCPResponse::ok(req.id.clone(), json!({ "tools": tools::manifest() })),
            "tools/call" => Self::call(req.id.clone(), req.params).await,
            "notifications/initialized" | "notifications/cancelled" => return None,
            other => MCPResponse::error(
                req.id.clone(),
                error_code::METHOD_NOT_FOUND,
                format!("This server does not implement {other:?}."),
            ),
        };

        (!is_notification).then_some(response)
    }

    async fn call(id: Option<Value>, params: Option<Value>) -> MCPResponse {
        let Some(params) = params else {
            return MCPResponse::error(
                id,
                error_code::INVALID_PARAMS,
                "tools/call needs a params object naming the tool and its arguments.",
            );
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return MCPResponse::error(id, error_code::INVALID_PARAMS, "tools/call needs a tool name.");
        };
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

        match tools::dispatch(name, &arguments).await {
            Ok(text) => MCPResponse::ok(
                id,
                json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false,
                }),
            ),
            Err(tools::ToolError::NotAuthorized(message)) => {
                // Reported as a tool result rather than a transport error, so
                // the calling model reads the explanation and can act on it
                // instead of retrying blindly.
                MCPResponse::ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": message }],
                        "isError": true,
                    }),
                )
            }
            Err(tools::ToolError::Unknown(name)) => MCPResponse::error(
                id,
                error_code::METHOD_NOT_FOUND,
                format!("There is no tool called {name:?}. Call tools/list for what there is."),
            ),
            Err(tools::ToolError::BadArguments(message)) => {
                MCPResponse::error(id, error_code::INVALID_PARAMS, message)
            }
            Err(tools::ToolError::Failed(message)) => MCPResponse::ok(
                id,
                json!({
                    "content": [{ "type": "text", "text": format!("The scan could not complete: {message}") }],
                    "isError": true,
                }),
            ),
        }
    }

    /// Read requests from `input` and write responses to `output`, one JSON
    /// document per line, until the input ends.
    pub async fn serve<R, W>(input: R, output: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncBufRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let mut lines = input.lines();
        let mut output = output;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<MCPRequest>(&line) {
                Ok(req) => Self::handle(req).await,
                Err(e) => Some(MCPResponse::error(
                    None,
                    error_code::PARSE_ERROR,
                    format!("Could not parse the request as JSON-RPC: {e}"),
                )),
            };
            if let Some(response) = response {
                output.write_all(serde_json::to_string(&response)?.as_bytes()).await?;
                output.write_all(b"\n").await?;
                output.flush().await?;
            }
        }
        Ok(())
    }

    /// Backwards-compatible synchronous entry point.
    ///
    /// The original API was blocking and returned a response for every request
    /// including notifications. Kept so an existing caller still compiles, but
    /// it cannot express "no reply", so a notification comes back as an empty
    /// success rather than as silence.
    pub fn handle_request(req: MCPRequest) -> MCPResponse {
        let id = req.id.clone();
        futures_executor_block_on(Self::handle(req))
            .unwrap_or_else(|| MCPResponse::ok(id, json!({})))
    }
}

/// Run one future to completion on the current thread.
///
/// `handle_request` is synchronous and public, so it needs somewhere to drive
/// the async handler. Building a single-threaded runtime per call is wasteful
/// but correct, and this path exists only for compatibility — everything that
/// matters goes through [`MCPServer::serve`].
fn futures_executor_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime can always be built")
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Value) -> MCPRequest {
        MCPRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: method.into(),
            params: Some(params),
        }
    }

    #[tokio::test]
    async fn initialize_advertises_the_protocol_version_and_the_tool_capability() {
        let r = MCPServer::handle(request("initialize", json!({}))).await.unwrap();
        let result = r.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "sentinelvapt");
    }

    /// The instructions are what tells a calling model that dynamic testing is
    /// gated. Without them it will keep trying.
    #[tokio::test]
    async fn initialize_states_the_authorisation_rule_up_front() {
        let r = MCPServer::handle(request("initialize", json!({}))).await.unwrap();
        let instructions = r.result.unwrap()["instructions"].as_str().unwrap().to_string();
        assert!(instructions.contains("Rules of Engagement"));
        assert!(instructions.contains("not a configurable behaviour"));
    }

    #[tokio::test]
    async fn tools_list_returns_every_tool_with_a_schema() {
        let r = MCPServer::handle(request("tools/list", json!({}))).await.unwrap();
        let tools = r.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(tools.len() >= 6, "got {} tools", tools.len());
        for tool in &tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].as_str().unwrap().len() > 60);
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    /// A notification has no id and must produce no reply at all.
    #[tokio::test]
    async fn a_notification_is_not_answered() {
        let notification = MCPRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/initialized".into(),
            params: None,
        };
        assert!(MCPServer::handle(notification).await.is_none());
    }

    #[tokio::test]
    async fn an_unknown_method_is_a_protocol_error_naming_the_method() {
        let r = MCPServer::handle(request("does/not/exist", json!({}))).await.unwrap();
        let error = r.error.unwrap();
        assert_eq!(error["code"], error_code::METHOD_NOT_FOUND);
        assert!(error["message"].as_str().unwrap().contains("does/not/exist"));
    }

    #[tokio::test]
    async fn an_unknown_tool_is_reported_with_a_pointer_to_the_tool_list() {
        let r = MCPServer::handle(request("tools/call", json!({ "name": "nope" })))
            .await
            .unwrap();
        let error = r.error.unwrap();
        assert_eq!(error["code"], error_code::METHOD_NOT_FOUND);
        assert!(error["message"].as_str().unwrap().contains("tools/list"));
    }

    #[tokio::test]
    async fn a_call_with_no_tool_name_is_an_invalid_params_error() {
        let r = MCPServer::handle(request("tools/call", json!({}))).await.unwrap();
        assert_eq!(r.error.unwrap()["code"], error_code::INVALID_PARAMS);
    }

    /// The single most important behaviour in this server.
    #[tokio::test]
    async fn dynamic_testing_without_an_authorisation_record_is_refused() {
        let r = MCPServer::handle(request(
            "tools/call",
            json!({
                "name": "assess_target",
                "arguments": { "target_url": "https://production-bank.example.com" }
            }),
        ))
        .await
        .unwrap();

        let result = r.result.expect("refusal is a tool result, not a transport error");
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Rules of Engagement"), "{text}");
        assert!(!text.contains("scan started"));
    }

    #[tokio::test]
    async fn a_malformed_line_yields_a_parse_error_rather_than_ending_the_session() {
        let input = "not json\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let mut output = Vec::new();
        MCPServer::serve(input.as_bytes(), &mut output).await.unwrap();

        let lines: Vec<&str> = std::str::from_utf8(&output).unwrap().lines().collect();
        assert_eq!(lines.len(), 2, "the session continued after the bad line");
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["error"]["code"], error_code::PARSE_ERROR);
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["id"], 2);
    }

    #[tokio::test]
    async fn a_notification_writes_nothing_to_the_stream() {
        let input = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let mut output = Vec::new();
        MCPServer::serve(input.as_bytes(), &mut output).await.unwrap();
        assert!(output.is_empty(), "a notification must produce no bytes");
    }

    #[tokio::test]
    async fn responses_are_one_json_document_per_line() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let mut output = Vec::new();
        MCPServer::serve(input.as_bytes(), &mut output).await.unwrap();
        for line in std::str::from_utf8(&output).unwrap().lines() {
            serde_json::from_str::<Value>(line).expect("each line parses on its own");
        }
    }
}
