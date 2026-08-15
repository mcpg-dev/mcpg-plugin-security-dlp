//! Data-loss-prevention ToolGate plugin (`dev.mcpg.tool-gate.dlp`).
//!
//! Scans tool **arguments** (pre-dispatch) and **results** (post-dispatch) for
//! secrets + PII via a configurable set of built-in regex detectors plus
//! operator custom patterns, and either **blocks** the call or **redacts** the
//! offending substrings. Pure logic — no network, no host services. The matched
//! secret value is NEVER echoed into a deny message, error data, logs, or metric
//! labels (only detector names + counts). Fails closed: a bad config or an
//! invalid regex refuses to load.

use mcpg_glob::glob_match;
use mcpg_plugin_protocol::{
    GateDecision, PluginContext, PluginManifest, firstparty_manifest, redact,
};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;

const PLUGIN_ID: &str = "dev.mcpg.tool-gate.dlp";
/// JSON-RPC error code for a DLP denial (governance/policy `-3205x` band).
const DENY_CODE: i32 = -32050;
const DENY_HTTP_STATUS: u16 = 403;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    /// Deny the call when a secret/PII is detected.
    Block,
    /// Allow the call but rewrite the offending substrings.
    Redact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    AwsAccessKey,
    AwsSecretKey,
    Jwt,
    Email,
    CreditCard,
    GenericApiKey,
    UrlCredentials,
}

impl DetectorKind {
    fn name(self) -> &'static str {
        match self {
            DetectorKind::AwsAccessKey => "aws_access_key",
            DetectorKind::AwsSecretKey => "aws_secret_key",
            DetectorKind::Jwt => "jwt",
            DetectorKind::Email => "email",
            DetectorKind::CreditCard => "credit_card",
            DetectorKind::GenericApiKey => "generic_api_key",
            DetectorKind::UrlCredentials => "url_credentials",
        }
    }

    fn pattern(self) -> &'static str {
        match self {
            DetectorKind::AwsAccessKey => {
                r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"
            }
            DetectorKind::AwsSecretKey => r"\b[A-Za-z0-9/+=]{40}\b",
            DetectorKind::Jwt => r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            DetectorKind::Email => r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            DetectorKind::CreditCard => r"\b(?:\d[ -]?){13,19}\b",
            DetectorKind::GenericApiKey => {
                r#"(?i)\b(?:api[_-]?key|secret|token|password|passwd|bearer)\b["':=\s]{1,4}[A-Za-z0-9_\-]{16,}"#
            }
            DetectorKind::UrlCredentials => r"(?i)://[^\s/:@]+:[^\s/@]+@",
        }
    }
}

fn default_detectors() -> Vec<DetectorKind> {
    use DetectorKind::*;
    vec![
        AwsAccessKey,
        AwsSecretKey,
        Jwt,
        Email,
        CreditCard,
        GenericApiKey,
        UrlCredentials,
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    #[serde(default = "default_true")]
    pub pre_execution: bool,
    #[serde(default = "default_true")]
    pub post_execution: bool,
    #[serde(default = "default_action")]
    pub action: DlpAction,
    #[serde(default = "default_detectors")]
    pub detectors: Vec<DetectorKind>,
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
    #[serde(default = "default_placeholder")]
    pub redact_placeholder: String,
    #[serde(default = "default_true")]
    pub redact_url_credentials: bool,
    #[serde(default = "default_true")]
    pub validate_credit_card_luhn: bool,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub exclude_tools: Vec<String>,
    #[serde(default)]
    pub apply_to_non_tool_surfaces: bool,
}

fn default_true() -> bool {
    true
}
fn default_action() -> DlpAction {
    DlpAction::Block
}
fn default_placeholder() -> String {
    "[REDACTED]".to_owned()
}

/// A compiled detector. `luhn` gates credit-card matches behind a mod-10 check;
/// `url` marks the URL-credential detector, which is redacted via the shared
/// `redact` module (userinfo strip) rather than placeholder substitution.
struct Detector {
    name: String,
    regex: Regex,
    luhn: bool,
    url: bool,
}

impl Detector {
    fn matches(&self, s: &str) -> bool {
        if self.luhn {
            self.regex.find_iter(s).any(|m| luhn_valid(m.as_str()))
        } else {
            self.regex.is_match(s)
        }
    }
}

/// Mod-10 (Luhn) check over the digits in `s` (separators ignored).
fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u8> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut v = d as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

pub struct DlpGatePlugin {
    manifest: PluginManifest,
    pre_execution: bool,
    post_execution: bool,
    action: DlpAction,
    detectors: Vec<Detector>,
    redact_placeholder: String,
    redact_url_credentials: bool,
    tools: Vec<String>,
    exclude_tools: Vec<String>,
    apply_to_non_tool_surfaces: bool,
}

impl DlpGatePlugin {
    /// SDK factory. Fails closed: a bad config or an invalid custom regex panics
    /// (→ null handle → boot Err), the uniform tool-gate convention.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: DlpConfig = serde_json::from_str(config_json)
            .unwrap_or_else(|err| panic!("tool-gate-dlp: config JSON failed to parse: {err}"));

        let mut detectors = Vec::new();
        for kind in &cfg.detectors {
            let regex = Regex::new(kind.pattern()).unwrap_or_else(|err| {
                panic!(
                    "tool-gate-dlp: built-in detector {} regex error: {err}",
                    kind.name()
                )
            });
            detectors.push(Detector {
                name: kind.name().to_owned(),
                regex,
                luhn: matches!(kind, DetectorKind::CreditCard) && cfg.validate_credit_card_luhn,
                url: matches!(kind, DetectorKind::UrlCredentials),
            });
        }
        for cp in &cfg.custom_patterns {
            let regex = Regex::new(&cp.regex).unwrap_or_else(|err| {
                panic!(
                    "tool-gate-dlp: custom pattern {:?} regex error: {err}",
                    cp.name
                )
            });
            detectors.push(Detector {
                name: cp.name.clone(),
                regex,
                luhn: false,
                url: false,
            });
        }

        Self {
            manifest: firstparty_manifest! {
                id: PLUGIN_ID,
                name: "Data-Loss-Prevention Gate",
                class: ToolGate,
            },
            pre_execution: cfg.pre_execution,
            post_execution: cfg.post_execution,
            action: cfg.action,
            detectors,
            redact_placeholder: cfg.redact_placeholder,
            redact_url_credentials: cfg.redact_url_credentials,
            tools: cfg.tools,
            exclude_tools: cfg.exclude_tools,
            apply_to_non_tool_surfaces: cfg.apply_to_non_tool_surfaces,
        }
    }

    fn matches_tool(&self, tool_name: &str) -> bool {
        if self.exclude_tools.iter().any(|p| glob_match(p, tool_name)) {
            return false;
        }
        self.tools.is_empty() || self.tools.iter().any(|p| glob_match(p, tool_name))
    }

    fn in_scope(&self, ctx: &PluginContext) -> bool {
        (ctx.surface == "tool" || self.apply_to_non_tool_surfaces)
            && self.matches_tool(&ctx.tool_name)
    }

    /// Collect the unique detector names that fire anywhere in `value`.
    fn scan(&self, value: &Value) -> Vec<String> {
        let mut found = Vec::new();
        self.scan_into(value, &mut found);
        found
    }

    fn scan_into(&self, value: &Value, found: &mut Vec<String>) {
        match value {
            Value::String(s) => {
                for d in &self.detectors {
                    if !found.iter().any(|n| n == &d.name) && d.matches(s) {
                        found.push(d.name.clone());
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|v| self.scan_into(v, found)),
            Value::Object(m) => m.values().for_each(|v| self.scan_into(v, found)),
            _ => {}
        }
    }

    /// Rewrite offending substrings in place: placeholder-substitute every
    /// non-URL detector match, then strip URL userinfo via the shared module.
    fn redact(&self, value: &mut Value) {
        self.redact_strings(value);
        if self.redact_url_credentials {
            redact::redact_value(value);
        }
    }

    fn redact_strings(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                let mut out = s.clone();
                for d in &self.detectors {
                    if d.url {
                        continue;
                    }
                    out = d
                        .regex
                        .replace_all(&out, self.redact_placeholder.as_str())
                        .into_owned();
                }
                *s = out;
            }
            Value::Array(a) => a.iter_mut().for_each(|v| self.redact_strings(v)),
            Value::Object(m) => m.values_mut().for_each(|v| self.redact_strings(v)),
            _ => {}
        }
    }

    fn enforce(&self, value: &Value, phase: &'static str, scanned: &str) -> GateDecision {
        let findings = self.scan(value);
        if findings.is_empty() {
            return GateDecision::allow();
        }
        let action_label = match self.action {
            DlpAction::Block => "block",
            DlpAction::Redact => "redact",
        };
        for name in &findings {
            metrics::counter!(
                "mcpg_dlp_findings_total",
                "detector" => name.clone(),
                "phase" => phase,
                "action" => action_label,
            )
            .increment(1);
        }
        // Detector NAMES only — never the matched secret value.
        warn!(phase, detectors = ?findings, "tool-gate-dlp: secret/PII detected");

        match self.action {
            DlpAction::Block => GateDecision::Deny {
                http_status: DENY_HTTP_STATUS,
                code: DENY_CODE,
                message: format!(
                    "DLP: secret/PII detected in {scanned}: {}",
                    findings.join(", ")
                ),
                error_data: Some(json!({ "detectors": findings, "count": findings.len() })),
            },
            DlpAction::Redact => {
                let mut redacted = value.clone();
                self.redact(&mut redacted);
                match phase {
                    "post" => GateDecision::Allow {
                        modified_arguments: None,
                        modified_result: Some(redacted),
                        metadata: None,
                    },
                    _ => GateDecision::Allow {
                        modified_arguments: Some(redacted),
                        modified_result: None,
                        metadata: None,
                    },
                }
            }
        }
    }
}

impl SyncToolGate for DlpGatePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        _meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if !self.pre_execution || !self.in_scope(ctx) {
            return GateDecision::allow();
        }
        let started = std::time::Instant::now();
        let decision = self.enforce(arguments, "pre", "arguments");
        metrics::histogram!("mcpg_dlp_evaluate_ms").record(started.elapsed().as_millis() as f64);
        decision
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        _arguments: &Value,
        result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        if !self.post_execution || !self.in_scope(ctx) {
            return GateDecision::allow();
        }
        let started = std::time::Instant::now();
        let decision = self.enforce(result, "post", "result");
        metrics::histogram!("mcpg_dlp_evaluate_ms").record(started.elapsed().as_millis() as f64);
        decision
    }
}

mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.tool-gate.dlp",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: DlpGatePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| DlpGatePlugin::from_config_json(cfg),
        },
    ],
}

#[cfg(test)]
mod tests;
