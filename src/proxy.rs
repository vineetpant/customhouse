//! The aggregating MCP proxy — the composition root and the enforcement point.
//!
//! `CustomhouseProxy` presents Customhouse to the client as a single MCP server that
//! exposes the merged, namespaced tools of its upstream servers and routes each
//! call back to the owning upstream. Enforcement happens in two places:
//!
//! - at connect, metadata pinning withholds any tool whose definition changed
//!   since it was pinned (§4), so it is never exposed in the first place;
//! - at call time, the §3 self-protection invariants are evaluated before the
//!   call is forwarded to any upstream.
//!
//! That call-time step is the single chokepoint every future policy decision
//! runs at; the Phase 1 taint and tiered-policy rules slot in there.

use std::path::Path;
use std::sync::Arc;

use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, GetPromptRequestParams, GetPromptResult,
        Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams,
        ReadResourceResult, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    transport::stdio,
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};

use crate::approval::{self, ApprovalOutcome, ApprovalStore};
use crate::config::Config;
use crate::decision::{Decision, InvariantOutcome};
use crate::destination;
use crate::flow::{CallRecipients, FlowPolicy};
use crate::invariant::Invariants;
use crate::ledger::Ledger;
use crate::pin::PinStore;
use crate::session::{SessionTaint, TaintSource};
use crate::sink::SinkMap;
use crate::upstream::{CallError, Registry, UpstreamError};
use tokio::sync::Mutex;

/// Customhouse presented to the client as a single aggregating MCP server.
///
/// Cheap to clone: the shared registry of upstream connections and the resolved
/// self-protection invariants live behind `Arc`s, so the proxy can be handed to
/// the MCP service by value.
#[derive(Clone)]
pub struct CustomhouseProxy {
    registry: Arc<Registry>,
    invariants: Arc<Invariants>,
    ledger: Arc<Ledger>,
    flow: Arc<FlowPolicy>,
    /// Accumulated taint for this session. stdio gives one session per process,
    /// so process lifetime is session lifetime (§6).
    ///
    /// The guard is held across the whole mediated call — assess, route, taint —
    /// which serialises mediated calls. That is deliberate: MCP clients dispatch
    /// requests concurrently, and without serialisation a sink call can be
    /// evaluated *before* an in-flight untrusted read has tainted the session,
    /// silently letting the exfiltration through. Correctness of the flow rule
    /// depends on taint from call N being visible to call N+1, so the ordering
    /// guarantee is worth more than tool-call parallelism the model does not use.
    taint: Arc<Mutex<SessionTaint>>,
    /// Operator approvals awaiting use. Re-read from disk on each escalation so
    /// an ack granted in another terminal takes effect without a restart —
    /// which is the whole point of an out-of-band approval.
    approvals: Arc<Mutex<ApprovalStore>>,
}

impl CustomhouseProxy {
    /// A proxy with no upstreams; advertises an empty tool set. Self-protection
    /// invariants are still resolved so the gate is never absent. The ledger is
    /// disabled here (this constructor is for tests that never route calls).
    pub fn empty() -> Self {
        Self {
            registry: Arc::new(Registry::empty()),
            invariants: Arc::new(Invariants::resolve(None)),
            ledger: Arc::new(Ledger::disabled()),
            flow: Arc::new(FlowPolicy::new(SinkMap::default(), Default::default())),
            taint: Arc::new(Mutex::new(SessionTaint::clean())),
            approvals: Arc::new(Mutex::new(ApprovalStore::open())),
        }
    }

    /// Connect every upstream in `config` and build the aggregated proxy.
    ///
    /// `config_path` is the file `config` was loaded from, if any; it is added
    /// to the protected set so a mediated call cannot rewrite it. The ledger and
    /// the invariant gate both resolve the same Customhouse home, so the ledger is
    /// written inside the directory the gate protects (I-5).
    pub async fn connect(
        config: &Config,
        config_path: Option<&Path>,
    ) -> Result<Self, UpstreamError> {
        let mut pins = PinStore::open();
        let (registry, events) = Registry::connect(&config.upstreams, &mut pins).await?;
        let ledger = Ledger::open();
        // Pins and withholds go to stderr for the operator and to the ledger as
        // the audit record.
        for event in &events {
            if let Some(summary) = event.summary() {
                eprintln!("customhouse: {summary}");
            }
            ledger.record_metadata(&event.server, &event.qualified_tool(), &event.outcome);
        }
        Ok(Self {
            registry: Arc::new(registry),
            invariants: Arc::new(Invariants::resolve(config_path)),
            ledger: Arc::new(ledger),
            flow: Arc::new(FlowPolicy::new(
                SinkMap::with_overrides(config.sinks.clone()),
                config.flow,
            )),
            taint: Arc::new(Mutex::new(SessionTaint::clean())),
            approvals: Arc::new(Mutex::new(ApprovalStore::open())),
        })
    }

    /// Number of tools currently exposed to the client.
    pub fn tool_count(&self) -> usize {
        self.registry.tools().len()
    }

    /// The identity Customhouse presents to clients on initialize.
    pub fn server_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            // MCP 2025-11-25 (ProtocolVersion::LATEST in rmcp 2.2.0).
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new("customhouse", crate::version()))
            .with_instructions("Customhouse: a deterministic proxy over your MCP servers.")
    }
}

impl ServerHandler for CustomhouseProxy {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(
            self.registry.tools().to_vec(),
        ))
    }

    // Surfaces Customhouse does not mediate yet are refused explicitly. The default
    // handlers for the `list_*` methods answer with an *empty* result, which
    // would tell the client "this server has no resources" — hiding whatever the
    // upstreams really expose and misrepresenting what is being protected. A
    // refusal is the honest answer: it is visible, and it cannot be mistaken for
    // a safe empty set (§5 — narrow and true beats broad and false).

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Err(unmediated("resources"))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Err(unmediated("resources"))
    }

    async fn read_resource(
        &self,
        _request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        Err(unmediated("resources"))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Err(unmediated("prompts"))
    }

    async fn get_prompt(
        &self,
        _request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        Err(unmediated("prompts"))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool = request.name.clone();

        // The pre-forward chokepoint: assess self-protection invariants (§3),
        // record the call (allowed and denied alike), then act. The ledger reads
        // the operator-only matched path from the assessment; the client sees
        // only the generic Decision reason. Phase 1 rules slot in right here.
        let assessment = self.invariants.assess(&request);
        let server = self.registry.server_of(&tool).map(str::to_string);
        let call_id = self
            .ledger
            .record_call(&request, server.as_deref(), &assessment);
        if let InvariantOutcome::Deny { reason } = assessment.outcome {
            eprintln!("customhouse: self-protection denied tool `{tool}`");
            return Err(McpError::invalid_params(reason, None));
        }

        // R3: a sink call is weighed against everything untrusted that has
        // already entered this session — including content from a *different*
        // upstream. This is the rule a per-server proxy cannot express.
        //
        // The guard is taken here and held until after any tainting below, so
        // concurrent requests cannot slip a sink past an in-flight untrusted read.
        let mut taint = self.taint.lock().await;
        // Recipients are read only from argument names the sink's upstream
        // declared. Undeclared stays undeclared rather than defaulting to an
        // empty list, because "we could not identify recipients" must not be
        // mistaken for "there were none" (§17.4).
        let recipients = server
            .as_deref()
            .map(|srv| {
                let fields = self.registry.recipient_fields_of(srv);
                CallRecipients {
                    declared: !fields.is_empty(),
                    values: collect_recipients(request.arguments.as_ref(), fields),
                }
            })
            .unwrap_or_default();
        let flow = self.flow.assess(&tool, &taint, &recipients);
        self.ledger.record_flow(&tool, &flow);
        match flow.decision {
            Decision::Allow => {}
            Decision::Deny { reason } => {
                eprintln!("customhouse: flow policy denied sink `{tool}`");
                return Err(McpError::invalid_params(reason, None));
            }
            Decision::Escalate { reason } => {
                // An operator may have acked this class out-of-band since the
                // session started, so consult the store rather than refusing
                // blind. Re-opening picks up an ack from another terminal.
                let class = flow.sink_class.expect("escalation implies a sink class");
                let mut approvals = self.approvals.lock().await;
                *approvals = ApprovalStore::open();
                let outcome = approvals.consume(class, approval::now_ms());
                let granted = matches!(outcome, ApprovalOutcome::Granted);
                if let Err(e) = approvals.save() {
                    eprintln!("customhouse: failed to persist approval use: {e}");
                }
                self.ledger.record_approval(class.as_str(), granted);

                if !granted {
                    let note = match outcome {
                        ApprovalOutcome::Expired => " A previous approval had expired.",
                        _ => "",
                    };
                    eprintln!("customhouse: flow policy escalated sink `{tool}` for approval");
                    return Err(McpError::invalid_params(format!("{reason}.{note}"), None));
                }
                eprintln!("customhouse: operator approval spent for `{tool}`");
            }
        }

        match self.registry.route_call(request).await {
            Ok(result) => {
                // Taint *before* handing the result back: the content is about
                // to enter the model's context, so the session is already
                // compromised by the time the client sees it. Error results
                // taint too — their content reaches the model either way.
                if let Some(server) = server {
                    if self.registry.trust_of(&server).is_untrusted() {
                        // Read the asserted author from the declared structured
                        // field. Never from searching the body (§17.2).
                        let author = self.registry.author_field_of(&server).and_then(|field| {
                            let text = result
                                .content
                                .first()
                                .and_then(|b| b.as_text())
                                .map(|t| t.text.as_str());
                            destination::author_from_result(
                                field,
                                result.structured_content.as_ref(),
                                text,
                            )
                        });
                        let source = TaintSource {
                            server,
                            tool: tool.to_string(),
                            call_id,
                            author,
                        };
                        self.ledger.record_taint(&source);
                        taint.taint(source);
                    }
                }
                Ok(result)
            }
            // An unknown tool is a client mistake (bad params); an upstream
            // failure is wrapped so its origin is preserved, not swallowed.
            Err(error @ CallError::UnknownTool { .. }) => {
                Err(McpError::invalid_params(error.to_string(), None))
            }
            Err(error) => Err(McpError::internal_error(error.to_string(), None)),
        }
    }
}

/// Pull recipient values out of the declared argument fields.
///
/// Only the named fields are read, and only string or array-of-string values.
/// Anything else contributes nothing, so a structure we do not understand can
/// never silently become an empty recipient set that satisfies the rule.
fn collect_recipients(
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
    fields: &[String],
) -> Vec<String> {
    let Some(args) = arguments else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for field in fields {
        match args.get(field) {
            Some(serde_json::Value::String(s)) => out.push(s.clone()),
            Some(serde_json::Value::Array(items)) => {
                out.extend(items.iter().filter_map(|i| i.as_str().map(str::to_string)));
            }
            _ => {}
        }
    }
    out
}

/// The error returned for an MCP surface Customhouse does not yet mediate.
///
/// Uses the protocol's method-not-found code, but with a message that says *why*
/// — an operator who points Customhouse at a resource-exposing server should learn
/// that those resources are being withheld deliberately, not conclude the server
/// is broken or empty.
fn unmediated(surface: &str) -> McpError {
    McpError::new(
        ErrorCode::METHOD_NOT_FOUND,
        format!(
            "customhouse does not mediate {surface} yet and will not pass them through \
             unchecked; only tools are mediated in this release"
        ),
        None,
    )
}

/// Failures starting or running the stdio serve loop.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Connect(#[from] UpstreamError),
    // Boxed because rmcp's serve error type is not exported on any public path,
    // so it cannot be named to hold it typed. This is a `#[source]` field, not a
    // return signature — the guideline exception for unnameable foreign errors.
    #[error("failed to start MCP server: {0}")]
    Server(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("server task failed: {0}")]
    Wait(#[from] tokio::task::JoinError),
}

/// Serve Customhouse as an MCP server over stdio until the client disconnects.
///
/// stdout carries the MCP protocol; all logging must go to stderr.
pub async fn serve_stdio(config: Config, config_path: Option<&Path>) -> Result<(), ServeError> {
    let proxy = CustomhouseProxy::connect(&config, config_path).await?;
    eprintln!(
        "customhouse {}: aggregating {} upstream(s), exposing {} tool(s)",
        crate::version(),
        config.upstreams.len(),
        proxy.tool_count(),
    );
    let running = proxy
        .serve(stdio())
        .await
        .map_err(|e| ServeError::Server(Box::new(e)))?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presents_as_customhouse() {
        let info = CustomhouseProxy::empty().server_info();
        assert_eq!(info.server_info.name, "customhouse");
        assert_eq!(info.server_info.version, crate::version());
    }

    #[test]
    fn negotiates_supported_protocol_version() {
        let info = CustomhouseProxy::empty().server_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn advertises_tools_capability() {
        let info = CustomhouseProxy::empty().server_info();
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn empty_proxy_exposes_no_tools() {
        assert_eq!(CustomhouseProxy::empty().tool_count(), 0);
    }

    #[test]
    fn unmediated_surfaces_are_refused_not_reported_empty() {
        // The failure this guards against is the *default* behaviour: answering
        // `resources/list` with an empty result, which reads to a client as "this
        // server has no resources" rather than "these are not being checked".
        for surface in ["resources", "prompts"] {
            let error = unmediated(surface);
            assert_eq!(error.code, ErrorCode::METHOD_NOT_FOUND);
            assert!(
                error.message.contains(surface) && error.message.contains("does not mediate"),
                "refusal must say which surface and why: {}",
                error.message
            );
        }
    }

    #[test]
    fn capabilities_advertise_only_what_is_mediated() {
        // Capabilities and refusals must agree: we advertise tools, so we must
        // not also be advertising surfaces the handlers refuse.
        let info = CustomhouseProxy::empty().server_info();
        assert!(info.capabilities.tools.is_some(), "tools are mediated");
        assert!(
            info.capabilities.resources.is_none(),
            "resources are refused, so must not be advertised"
        );
        assert!(
            info.capabilities.prompts.is_none(),
            "prompts are refused, so must not be advertised"
        );
    }
}
