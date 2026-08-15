use mcpg_plugin_protocol::{GateDecision, PluginContext, PluginIdentity};
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde_json::{Value, json};

use super::{DlpGatePlugin, PLUGIN_ID};

fn ctx(tool: &str, surface: &str) -> PluginContext {
    PluginContext {
        request_id: "t".into(),
        session_id: None,
        tool_name: tool.into(),
        surface: surface.into(),
        identity: PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: Default::default(),
        },
        transport: "http".into(),
    }
}

fn build(cfg: Value) -> DlpGatePlugin {
    DlpGatePlugin::from_config_json(&cfg.to_string())
}

fn pre(p: &DlpGatePlugin, args: Value) -> GateDecision {
    p.evaluate_pre(&ctx("some.tool", "tool"), &args, None, &json!({}))
}

fn deny_of(d: GateDecision) -> (u16, i32, String, Option<Value>) {
    match d {
        GateDecision::Deny {
            http_status,
            code,
            message,
            error_data,
        } => (http_status, code, message, error_data),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn manifest_is_correct() {
    use mcpg_plugin_protocol::PluginClass;
    let p = build(json!({ "detectors": ["email"] }));
    let m = SyncToolGate::manifest(&p);
    assert_eq!(m.id, PLUGIN_ID);
    assert_eq!(m.plugin_class, PluginClass::ToolGate);
    assert_eq!(m.protocol_version, "1.0");
    assert!(m.required_capabilities.is_empty());
}

#[test]
fn aws_access_key_detected_and_blocked() {
    let p = build(json!({ "detectors": ["aws_access_key"], "action": "block" }));
    let d = pre(&p, json!({ "k": "AKIAIOSFODNN7EXAMPLE" }));
    let (status, code, msg, data) = deny_of(d);
    assert_eq!(status, 403);
    assert_eq!(code, -32050);
    assert!(msg.contains("aws_access_key"), "{msg}");
    // SECURITY: never echo the matched secret.
    assert!(
        !msg.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret leaked in message: {msg}"
    );
    let data = data.unwrap().to_string();
    assert!(
        !data.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret leaked in error_data: {data}"
    );
}

#[test]
fn jwt_detected() {
    let p = build(json!({ "detectors": ["jwt"], "action": "block" }));
    let tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlX2hlcmU";
    assert!(matches!(
        pre(&p, json!({ "t": tok })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn email_detected_in_nested_object_and_array() {
    let p = build(json!({ "detectors": ["email"], "action": "block" }));
    assert!(matches!(
        pre(&p, json!({ "user": { "email": "a@b.com" } })),
        GateDecision::Deny { .. }
    ));
    assert!(matches!(
        pre(&p, json!({ "xs": ["plain", "a@b.com"] })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn credit_card_luhn_true_positive() {
    let p = build(json!({ "detectors": ["credit_card"], "action": "block" }));
    assert!(matches!(
        pre(&p, json!({ "cc": "4111111111111111" })),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn credit_card_luhn_false_positive_rejected() {
    let p = build(
        json!({ "detectors": ["credit_card"], "action": "block", "validate_credit_card_luhn": true }),
    );
    // Invalid Luhn checksum → not a finding.
    assert!(matches!(
        pre(&p, json!({ "cc": "4111111111111112" })),
        GateDecision::Allow { .. }
    ));
}

#[test]
fn no_findings_allows() {
    let p = build(json!({ "detectors": ["email", "aws_access_key"], "action": "block" }));
    assert!(matches!(
        pre(&p, json!({ "q": "hello world" })),
        GateDecision::Allow { .. }
    ));
}

#[test]
fn redact_mode_rewrites_arguments() {
    let p = build(json!({ "detectors": ["email"], "action": "redact" }));
    match pre(&p, json!({ "e": "reach a@b.com please" })) {
        GateDecision::Allow {
            modified_arguments: Some(v),
            ..
        } => {
            let s = v["e"].as_str().unwrap();
            assert!(s.contains("[REDACTED]"), "{s}");
            assert!(!s.contains("a@b.com"), "{s}");
        }
        other => panic!("expected Allow w/ modified_arguments, got {other:?}"),
    }
}

#[test]
fn redact_mode_post_rewrites_result() {
    let p = build(json!({ "detectors": ["email"], "action": "redact" }));
    let d = p.evaluate_post(
        &ctx("some.tool", "tool"),
        &json!({}),
        &json!({ "out": "a@b.com" }),
        1,
        &json!({}),
    );
    match d {
        GateDecision::Allow {
            modified_result: Some(v),
            modified_arguments: None,
            ..
        } => {
            assert!(!v["out"].as_str().unwrap().contains("a@b.com"));
        }
        other => panic!("expected Allow w/ modified_result, got {other:?}"),
    }
}

#[test]
fn block_mode_post_denies_mentioning_result() {
    let p = build(json!({ "detectors": ["email"], "action": "block" }));
    let d = p.evaluate_post(
        &ctx("some.tool", "tool"),
        &json!({}),
        &json!({ "out": "a@b.com" }),
        1,
        &json!({}),
    );
    let (_, _, msg, _) = deny_of(d);
    assert!(msg.contains("result"), "{msg}");
}

#[test]
fn url_credentials_redacted() {
    let p = build(
        json!({ "detectors": ["url_credentials"], "action": "redact", "redact_url_credentials": true }),
    );
    match pre(&p, json!({ "dsn": "postgres://u:p@db/app" })) {
        GateDecision::Allow {
            modified_arguments: Some(v),
            ..
        } => {
            assert_eq!(v["dsn"], json!("postgres://db/app"));
        }
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn custom_pattern_compiled_and_matched() {
    let p = build(json!({
        "detectors": [],
        "action": "block",
        "custom_patterns": [{ "name": "emp_id", "regex": "EMP-[0-9]{6}" }]
    }));
    let (_, _, msg, _) = deny_of(pre(&p, json!({ "x": "id EMP-123456" })));
    assert!(msg.contains("emp_id"), "{msg}");
}

#[test]
fn tool_filtering_include_exclude() {
    let p = build(json!({
        "detectors": ["email"], "action": "block",
        "tools": ["finance.*"], "exclude_tools": ["finance.debug_*"]
    }));
    let secret = json!({ "e": "a@b.com" });
    // included
    assert!(matches!(
        p.evaluate_pre(&ctx("finance.transfer", "tool"), &secret, None, &json!({})),
        GateDecision::Deny { .. }
    ));
    // excluded (exclude wins)
    assert!(matches!(
        p.evaluate_pre(
            &ctx("finance.debug_dump", "tool"),
            &secret,
            None,
            &json!({})
        ),
        GateDecision::Allow { .. }
    ));
    // not in include set
    assert!(matches!(
        p.evaluate_pre(&ctx("other.tool", "tool"), &secret, None, &json!({})),
        GateDecision::Allow { .. }
    ));
}

#[test]
fn non_tool_surface_skipped_unless_opted_in() {
    let p = build(json!({ "detectors": ["email"], "action": "block" }));
    assert!(matches!(
        p.evaluate_pre(
            &ctx("some.tool", "resource"),
            &json!({ "e": "a@b.com" }),
            None,
            &json!({})
        ),
        GateDecision::Allow { .. }
    ));
    let opted = build(
        json!({ "detectors": ["email"], "action": "block", "apply_to_non_tool_surfaces": true }),
    );
    assert!(matches!(
        opted.evaluate_pre(
            &ctx("some.tool", "resource"),
            &json!({ "e": "a@b.com" }),
            None,
            &json!({})
        ),
        GateDecision::Deny { .. }
    ));
}

#[test]
fn pre_execution_false_skips_pre() {
    let p = build(json!({ "detectors": ["email"], "action": "block", "pre_execution": false }));
    assert!(matches!(
        pre(&p, json!({ "e": "a@b.com" })),
        GateDecision::Allow { .. }
    ));
}

#[test]
fn post_execution_false_skips_post() {
    let p = build(json!({ "detectors": ["email"], "action": "block", "post_execution": false }));
    let d = p.evaluate_post(
        &ctx("some.tool", "tool"),
        &json!({}),
        &json!({ "out": "a@b.com" }),
        1,
        &json!({}),
    );
    assert!(matches!(d, GateDecision::Allow { .. }));
}

#[test]
fn detector_subset_config() {
    let p = build(json!({ "detectors": ["email"], "action": "block" }));
    // AWS key NOT flagged (detector disabled); email IS flagged.
    assert!(matches!(
        pre(&p, json!({ "k": "AKIAIOSFODNN7EXAMPLE" })),
        GateDecision::Allow { .. }
    ));
    assert!(matches!(
        pre(&p, json!({ "e": "a@b.com" })),
        GateDecision::Deny { .. }
    ));
}

#[test]
#[should_panic(expected = "config JSON failed to parse")]
fn malformed_config_json_panics_fail_closed() {
    DlpGatePlugin::from_config_json("{ not json");
}

#[test]
#[should_panic(expected = "config JSON failed to parse")]
fn unknown_top_level_config_key_rejected() {
    DlpGatePlugin::from_config_json(&json!({ "detectors": ["email"], "bogus": 1 }).to_string());
}

#[test]
#[should_panic(expected = "regex error")]
fn invalid_custom_regex_panics_fail_closed() {
    DlpGatePlugin::from_config_json(
        &json!({ "detectors": [], "custom_patterns": [{ "name": "bad", "regex": "(" }] })
            .to_string(),
    );
}
