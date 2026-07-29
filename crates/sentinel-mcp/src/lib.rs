use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<serde_json::Value>,
}

pub struct MCPServer;

impl MCPServer {
    /// Dispatches Model Context Protocol (MCP) tool requests
    pub fn handle_request(req: MCPRequest) -> MCPResponse {
        match req.method.as_str() {
            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "verify_target_authorization",
                            "description": "Verifies target URL scope against Authorization Gate and Rules of Engagement (RoE)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target_url": { "type": "string" }
                                },
                                "required": ["target_url"]
                            }
                        },
                        {
                            "name": "run_vapt_scan",
                            "description": "Dispatches multi-engine containerized security assessment (ZAP, Nuclei, Semgrep, Trivy, Gitleaks)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target_url": { "type": "string" }
                                },
                                "required": ["target_url"]
                            }
                        },
                        {
                            "name": "generate_dual_reports",
                            "description": "Generates Client Executive and Developer Technical HTML/PDF reports",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "company_name": { "type": "string" }
                                },
                                "required": ["company_name"]
                            }
                        }
                    ]
                });

                MCPResponse {
                    jsonrpc: "2.0".into(),
                    id: req.id,
                    result: Some(tools),
                    error: None,
                }
            },
            _ => MCPResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: None,
                error: Some(json!({ "code": -32601, "message": "Method not found" })),
            }
        }
    }
}
