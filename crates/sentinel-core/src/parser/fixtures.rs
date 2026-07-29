pub const SEMGREP_FIXTURE_JSON: &str = r#"{
  "results": [
    {
      "check_id": "javascript.express.security.sqli.express-sqli",
      "path": "src/controllers/searchController.ts",
      "start": { "line": 34 },
      "extra": {
        "message": "User input flowing directly into raw database query string.",
        "severity": "ERROR",
        "lines": "const res = await db.query('SELECT * FROM users WHERE search = ' + req.query.q);"
      }
    }
  ]
}"#;

pub const ZAP_FIXTURE_JSON: &str = r#"{
  "site": [
    {
      "alerts": [
        {
          "name": "SQL Injection in Search Endpoint",
          "desc": "DAST parameter injection verified SQL error on query.",
          "riskdesc": "High (High)",
          "cweid": "89",
          "solution": "Use parameterized prepared statements.",
          "url": "https://portal.acme-corp.internal/api/v1/users/search",
          "param": "q"
        }
      ]
    }
  ]
}"#;

pub const TRIVY_FIXTURE_JSON: &str = r#"{
  "Results": [
    {
      "Target": "package-lock.json",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-29041",
          "PkgName": "express",
          "InstalledVersion": "4.18.1",
          "FixedVersion": "4.19.2",
          "Title": "Open Redirect via malformed URLs",
          "Description": "Express open redirect vulnerability in URL parser.",
          "Severity": "HIGH"
        }
      ]
    }
  ]
}"#;

pub const GITLEAKS_FIXTURE_JSON: &str = r#"[
  {
    "Description": "AWS Access Key Secret",
    "File": "src/config/aws.ts",
    "StartLine": 14,
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "RuleID": "aws-access-token"
  }
]"#;

pub const NUCLEI_FIXTURE_JSONL: &str = r#"{"template-id":"env-file-exposure","info":{"name":"Exposed Environment Configuration File","description":".env file publicly accessible on server","severity":"critical"},"matched-at":"https://portal.acme-corp.internal/.env"}"#;
