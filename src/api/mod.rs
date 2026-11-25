//! The HTTP API Sonder talks to (CONTRACT.md is its consumer's description): the
//! manifest, read-only SQL over the query log, and runtime actions.
//!
//! Every route needs `Authorization: Bearer <secret>`. SQL runs on blocking threads, at
//! most `api.max_concurrent` at once, so a heavy dashboard never holds up DNS, which
//! answers on the async workers.

pub mod manifest;
pub mod readonly;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::{error, info, warn};

use crate::clients;
use crate::config::Config;
use crate::dns::answer::rewrite_for;
use crate::dns::pipeline::{current, LiveConfig, Pipeline, Shared};
use crate::dns::upstream::Upstream;
use crate::lists::{Fetch, Lists};
use crate::rules::{RuleSet, Verdict};
use manifest::{ActionId, PAUSE_MINUTES};
use readonly::{run_query, Frame, ParamValue, QueryError, QueryLimits};

/// A query waits this long for a free slot, then gets 429.
const BUSY_WAIT: Duration = Duration::from_secs(2);
/// Request bodies are SQL plus a few params; SQLite refuses SQL over 100,000 bytes.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// A query result goes out in chunks of about this size, at most `CHUNKS_QUEUED`
/// written ahead of the client.
const CHUNK_BYTES: usize = 64 * 1024;
const CHUNKS_QUEUED: usize = 4;
/// A client that takes no chunk for this long loses the rest of the response, so a
/// stalled reader cannot hold a query slot (and its result's memory) forever.
const STALLED_CLIENT: Duration = Duration::from_secs(30);
const MAX_NAME_BYTES: usize = 253;

/// Held for the whole of every CPU- or timing-heavy test (here and in `readonly`), so
/// those never run at the same time and squeeze each other's time limits. A tokio mutex,
/// so async tests can hold it across `.await`; sync tests take it with `blocking_lock`.
#[cfg(test)]
pub(crate) static HEAVY_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the actions act on: the running DNS state and where the config lives.
pub struct Runtime<F: Fetch, U: Upstream> {
    pub config_path: PathBuf,
    pub db_path: PathBuf,
    pub pipeline: Arc<Pipeline<U>>,
    pub lists: Arc<Lists<F>>,
    pub rules: Shared<RuleSet>,
    pub live: Shared<LiveConfig>,
}

pub struct ApiState<F: Fetch, U: Upstream> {
    /// None: no secret configured, every request is refused.
    secret: Option<Vec<u8>>,
    /// Why the query log could not open, if it could not (queries then get 503).
    store: Result<(), String>,
    limits: QueryLimits,
    /// One permit per query allowed to run; an `Arc` so a permit can move onto the
    /// blocking thread and live until the result is written out.
    permits: Arc<Semaphore>,
    /// Written once: it never changes while running.
    manifest: Bytes,
    /// `STALLED_CLIENT`; shorter in tests.
    stall: Duration,
    runtime: Runtime<F, U>,
}

impl<F: Fetch, U: Upstream> ApiState<F, U> {
    pub fn new(
        secret: Option<Vec<u8>>,
        store: Result<(), String>,
        limits: QueryLimits,
        max_concurrent: usize,
        runtime: Runtime<F, U>,
    ) -> Self {
        let manifest = serde_json::to_vec(&manifest::manifest(max_concurrent))
            .expect("the manifest is plain data");
        ApiState {
            secret,
            store,
            limits,
            permits: Arc::new(Semaphore::new(max_concurrent)),
            manifest: Bytes::from(manifest),
            stall: STALLED_CLIENT,
            runtime,
        }
    }
}

/// The bearer secret from its mounted file, surrounding whitespace trimmed. Missing or
/// empty means no secret: every request then gets 503 (fail closed), and DNS runs on.
pub fn read_secret(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) if !bytes.trim_ascii().is_empty() => Some(bytes.trim_ascii().to_vec()),
        Ok(_) => {
            warn!(path = %path.display(), "api secret file is empty, every api request gets 503");
            None
        }
        Err(e) => {
            warn!(path = %path.display(), "api secret not read, every api request gets 503: {e}");
            None
        }
    }
}

/// Serves the API on `listener` until the process ends.
pub async fn serve<F: Fetch + 'static, U: Upstream + 'static>(
    listener: tokio::net::TcpListener,
    state: Arc<ApiState<F, U>>,
) {
    if let Err(e) = axum::serve(listener, router(state)).await {
        error!("api server stopped: {e}");
    }
}

pub fn router<F: Fetch + 'static, U: Upstream + 'static>(state: Arc<ApiState<F, U>>) -> Router {
    Router::new()
        .route("/integration/manifest", get(get_manifest::<F, U>))
        .route("/integration/query", post(query::<F, U>))
        .route("/integration/actions/{id}", post(action::<F, U>))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "no such route") })
        // `layer` (unlike `route_layer`) also wraps the fallback: unknown paths are
        // refused the same way.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::<F, U>,
        ))
        .with_state(state)
}

type AppState<F, U> = State<Arc<ApiState<F, U>>>;

async fn auth<F: Fetch, U: Upstream>(
    State(s): AppState<F, U>,
    req: Request,
    next: Next,
) -> Response {
    let Some(secret) = &s.secret else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "api secret not configured");
    };
    let Some(given) = req.headers().get(header::AUTHORIZATION) else {
        return error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    match given.as_bytes().strip_prefix(b"Bearer ") {
        Some(token) if same_secret(token, secret) => next.run(req).await,
        _ => error(StatusCode::UNAUTHORIZED, "wrong bearer token"),
    }
}

/// Takes the same time wherever the first difference is, so response times cannot
/// reveal the secret byte by byte. Only the length can show.
fn same_secret(given: &[u8], secret: &[u8]) -> bool {
    if given.len() != secret.len() {
        return false;
    }
    let diff = given
        .iter()
        .zip(secret)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    // black_box keeps the optimizer from turning the fold back into an early exit.
    std::hint::black_box(diff) == 0
}

fn json_response(status: StatusCode, body: impl Into<Body>) -> Response {
    let mime = [(header::CONTENT_TYPE, "application/json")];
    (status, mime, body.into()).into_response()
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    json_response(status, json!({ "error": message.into() }).to_string())
}

/// The body as JSON, or the 400 to answer with. An empty body is `T::default()`.
async fn read_json<T: DeserializeOwned + Default>(body: Body) -> Result<T, Response> {
    let bad = |message: String| error(StatusCode::BAD_REQUEST, message);
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|e| bad(format!("reading the request body: {e}")))?;
    if bytes.trim_ascii().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(&bytes).map_err(|e| bad(format!("bad request body: {e}")))
}

async fn get_manifest<F: Fetch, U: Upstream>(State(s): AppState<F, U>) -> Response {
    json_response(StatusCode::OK, s.manifest.clone())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryRequest {
    /// Missing is refused below; a default lets an empty body reach that message.
    #[serde(default)]
    sql: Option<String>,
    #[serde(default)]
    params: BTreeMap<String, ParamValue>,
}

async fn query<F: Fetch, U: Upstream>(State(s): AppState<F, U>, body: Body) -> Response {
    if let Err(reason) = &s.store {
        let message = format!("log store unavailable: {reason}");
        return error(StatusCode::SERVICE_UNAVAILABLE, message);
    }
    let req: QueryRequest = match read_json(body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let Some(sql) = req.sql else {
        return error(StatusCode::BAD_REQUEST, "the request has no sql");
    };
    let wait = tokio::time::timeout(BUSY_WAIT, Arc::clone(&s.permits).acquire_owned()).await;
    // acquire_owned fails only on a closed semaphore, which never happens here.
    let Ok(Ok(permit)) = wait else {
        return error(StatusCode::TOO_MANY_REQUESTS, "busy");
    };

    let (db, limits, stall) = (s.runtime.db_path.clone(), s.limits, s.stall);
    let (outcome_tx, outcome) = oneshot::channel();
    let (chunks_tx, chunks) = mpsc::channel(CHUNKS_QUEUED);
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        // Held until the result is written out and freed, so at most max_concurrent
        // results are ever in memory.
        let _permit = permit;
        match run_query(&db, &sql, &req.params, &limits) {
            Err(e) => {
                let _ = outcome_tx.send(Err(e));
            }
            // A failed send means the client is gone: nobody to stream to.
            Ok(frame) => {
                if outcome_tx.send(Ok(())).is_ok() {
                    stream_frame(frame, &|chunk| {
                        let send = tokio::time::timeout(stall, chunks_tx.send(chunk));
                        matches!(runtime.block_on(send), Ok(Ok(())))
                    });
                }
            }
        }
    });
    match outcome.await {
        Ok(Ok(())) => json_response(StatusCode::OK, Body::new(FrameBody(chunks))),
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, query_error(&e, &limits)),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "the query thread failed"),
    }
}

/// Everything a query can fail with is the query's doing (bad SQL, a write, a limit),
/// so all of it is a 400. Matched in full so a new variant gets a decision here.
fn query_error(e: &QueryError, limits: &QueryLimits) -> String {
    match e {
        QueryError::Timeout => format!("{e} of {} ms", limits.timeout.as_millis()),
        QueryError::NotReadOnly(_)
        | QueryError::MultipleStatements
        | QueryError::UnknownParam(_)
        | QueryError::TooManyFunctions { .. }
        | QueryError::ResultTooLarge { .. }
        | QueryError::Sql(_) => e.to_string(),
    }
}

/// Writes `frame` as JSON in chunks, freeing each row once written, so the result is
/// never held twice (rows plus their JSON). The shape is `Frame`'s serde derive, which
/// a test checks. `send` returns false when the client is gone or stalled; the rest is
/// then dropped.
fn stream_frame(frame: Frame, send: &dyn Fn(Bytes) -> bool) {
    let Frame {
        columns,
        rows,
        truncated,
        elapsed_ms,
    } = frame;
    let mut buf = Vec::with_capacity(2 * CHUNK_BYTES);
    buf.extend_from_slice(b"{\"columns\":");
    if !write_json(&mut buf, &columns) {
        return;
    }
    buf.extend_from_slice(b",\"rows\":[");
    for (i, row) in rows.into_iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        if !write_json(&mut buf, &row) {
            return;
        }
        if buf.len() >= CHUNK_BYTES {
            let full = std::mem::replace(&mut buf, Vec::with_capacity(2 * CHUNK_BYTES));
            if !send(Bytes::from(full)) {
                return;
            }
        }
    }
    // Writing into a Vec cannot fail.
    let _ = write!(
        buf,
        "],\"truncated\":{truncated},\"elapsedMs\":{elapsed_ms}}}"
    );
    send(Bytes::from(buf));
}

/// serde_json writing into a Vec cannot fail for these types; if it ever did, the
/// response would end early, so it is logged.
fn write_json(buf: &mut Vec<u8>, value: &impl Serialize) -> bool {
    match serde_json::to_writer(&mut *buf, value) {
        Ok(()) => true,
        Err(e) => {
            error!("writing a query result: {e}");
            false
        }
    }
}

/// The response body of a query: chunks as `stream_frame` sends them.
struct FrameBody(mpsc::Receiver<Bytes>);

impl http_body::Body for FrameBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(cx)
            .map(|chunk| chunk.map(|c| Ok(http_body::Frame::data(c))))
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    #[serde(default)]
    params: Map<String, Value>,
}

async fn action<F: Fetch + 'static, U: Upstream + 'static>(
    State(s): AppState<F, U>,
    UrlPath(id): UrlPath<String>,
    body: Body,
) -> Response {
    let Some(action) = ActionId::from_id(&id) else {
        return error(StatusCode::NOT_FOUND, format!("no action {id:?}"));
    };
    let req: ActionRequest = match read_json(body).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let rt = &s.runtime;
    let (ok, message) = match action {
        ActionId::Pause => pause(rt, &req.params),
        ActionId::Resume => {
            rt.pipeline.resume();
            (true, "blocking resumed".to_string())
        }
        ActionId::RefreshLists => {
            let report = rt.lists.refresh().await;
            let ok = report.per_list.iter().all(|(_, r)| r.is_ok());
            (ok, report.summary())
        }
        ActionId::ReloadConfig => reload_config(rt).await,
        ActionId::TestDomain => test_domain(rt, &req.params),
    };
    info!(action = id, ok, "{message}");
    json_response(
        StatusCode::OK,
        json!({ "ok": ok, "message": message }).to_string(),
    )
}

fn pause<F: Fetch, U: Upstream + 'static>(
    rt: &Runtime<F, U>,
    params: &Map<String, Value>,
) -> (bool, String) {
    let (lo, hi) = PAUSE_MINUTES;
    match params.get("minutes").and_then(Value::as_i64) {
        Some(m) if (lo..=hi).contains(&m) => {
            rt.pipeline
                .pause(Duration::from_secs(m.unsigned_abs() * 60));
            (true, format!("blocking paused for {m} minutes"))
        }
        _ => (
            false,
            format!("minutes must be a whole number from {lo} to {hi}"),
        ),
    }
}

/// Re-reads config.toml and applies what can change while running: lists and user
/// rules (rebuilt from the bodies on disk), rewrites, refused names, blocked TTL and
/// device names. Lists newly in force are fetched in the background. A config that does
/// not load changes nothing.
async fn reload_config<F: Fetch + 'static, U: Upstream>(rt: &Runtime<F, U>) -> (bool, String) {
    let config = match Config::load(&rt.config_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                false,
                format!("config not reloaded, the running one stays: {e:#}"),
            )
        }
    };
    let fresh = match rt
        .lists
        .set_config(config.lists.clone(), config.user_rules.clone())
        .await
    {
        Ok(fresh) => fresh,
        Err(e) => {
            return (
                false,
                format!("rule set not rebuilt, the running rules stay: {e:#}"),
            )
        }
    };
    // Replaced whole, never edited in place: a query in flight keeps the Arc it read.
    *rt.live.write().unwrap_or_else(PoisonError::into_inner) =
        Arc::new(LiveConfig::from_config(&config));

    let mut message = format!(
        "config reloaded: {} lists, {} user rules, {} rewrites, {} device names",
        config.lists.len(),
        config.user_rules.len(),
        config.rewrites.len(),
        config.devices.len()
    );
    let (db, devices) = (rt.db_path.clone(), config.devices);
    match tokio::task::spawn_blocking(move || clients::apply_config_names(&db, &devices)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = write!(message, "; device names not saved: {e:#}");
        }
        Err(e) => {
            let _ = write!(message, "; device names not saved: {e}");
        }
    }
    // Their bodies on disk are missing or from the old URL. Not awaited: a fetch can
    // take 30 s per list. The refresh lock queues it behind any refresh running.
    if !fresh.is_empty() {
        let plural = if fresh.len() == 1 { "" } else { "s" };
        let _ = write!(message, "; refreshing {} new list{plural}", fresh.len());
        let lists = Arc::clone(&rt.lists);
        tokio::spawn(async move {
            // Not inside `info!`: tracing skips a macro's arguments when the level is
            // off, and the refresh would never run.
            let report = lists.refresh().await;
            info!("{}", report.summary());
        });
    }
    // What `Config` holds that nothing above swaps in: read once at startup.
    message.push_str(
        ". [upstreams], dns.listen, dns.max_inflight, dns.router and the [api] and [store] \
         sections apply at the next restart.",
    );
    (true, message)
}

/// What lacuna would answer for a name, in the pipeline's order: refused names,
/// rewrites, then the rules. `ok` is false only for a name that is not one.
fn test_domain<F: Fetch, U: Upstream + 'static>(
    rt: &Runtime<F, U>,
    params: &Map<String, Value>,
) -> (bool, String) {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return (false, "name must be a domain name".to_string());
    }
    let live = current(&rt.live);
    let refused = live
        .refused_names
        .iter()
        .any(|r| r.trim_end_matches('.').eq_ignore_ascii_case(&name));
    if refused {
        return (true, "refused: lacuna never answers this name".to_string());
    }
    if let Some(a) = rewrite_for(&live.rewrites, &name) {
        return (true, format!("rewritten to {a}"));
    }
    let list = |id: u32| {
        rt.lists
            .list_name(id)
            .unwrap_or_else(|| format!("list {id}"))
    };
    let verdict = match current(&rt.rules).check(&name) {
        Verdict::Pass => return (true, "allowed".to_string()),
        Verdict::Allow { list_id, rule } => {
            return (true, format!("allowed by {rule} ({})", list(list_id)))
        }
        Verdict::Block { list_id, rule } => format!("blocked by {rule} ({})", list(list_id)),
        Verdict::HostsIp { ip, list_id, rule } => {
            format!("answered {ip} by {rule} ({})", list(list_id))
        }
    };
    if rt.pipeline.is_paused_now() {
        (
            true,
            format!("allowed: blocking is paused (otherwise {verdict})"),
        )
    } else {
        (true, verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::manifest::{manifest, ActionId};
    use super::readonly::{run_query, Frame, ParamValue};
    use super::*;
    use crate::codes::{Outcome, Reason, ServedFrom, Source};
    use crate::config::ListConfig;
    use crate::dns::pipeline::testing::{live, upstreams, Fake, State};
    use crate::dns::pipeline::{current, shared, NoopSink, QueryRecord};
    use crate::dns::server::{self, Listeners};
    use crate::dns::upstream::UdpUpstream;
    use crate::store::testing::{record, TempDb};
    use crate::store::{rollup, writer, Store};
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request};
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    const SECRET: &str = "s3cret-for-tests";
    const AUTH: &str = "Bearer s3cret-for-tests";
    const DEPLOY: &str = include_str!("../../deploy/config.toml");
    const LIST_NAME: &str = "AdGuard DNS filter";

    /// Serves the bodies set in it by URL; any other URL fails.
    #[derive(Clone, Default)]
    struct TestFetch(Arc<std::sync::Mutex<BTreeMap<String, String>>>);

    impl TestFetch {
        fn serve(&self, url: &str, body: &str) {
            self.0.lock().unwrap().insert(url.into(), body.into());
        }
    }

    impl Fetch for TestFetch {
        async fn fetch(&self, url: &str) -> Result<String, String> {
            let body = self.0.lock().unwrap().get(url).cloned();
            body.ok_or_else(|| "offline in tests".to_string())
        }
    }

    /// List 1 in deploy/config.toml, so reloading that file does not move it.
    const LIST_1_URL: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt";

    struct Rig {
        state: Arc<ApiState<TestFetch, Fake>>,
        app: Router,
        fetch: TestFetch,
        db: TempDb,
        /// Holds the config file and the lists dir; removed on drop.
        dir: PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Setup {
        secret: Option<&'static str>,
        store: Result<(), String>,
        limits: QueryLimits,
        max_concurrent: usize,
        stall: Duration,
    }

    impl Default for Setup {
        fn default() -> Self {
            Setup {
                secret: Some(SECRET),
                store: Ok(()),
                limits: QueryLimits {
                    timeout: Duration::from_secs(5),
                    row_cap: 10_000,
                },
                max_concurrent: 2,
                stall: STALLED_CLIENT,
            }
        }
    }

    /// A migrated log, list 1 blocking `||adnet.com^` on disk, the deploy config on disk.
    fn rig(tag: &str, setup: Setup) -> Rig {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let db = TempDb::new(tag);
        drop(Store::open(&db.0).unwrap());
        let dir = std::env::temp_dir().join(format!(
            "lacuna-api-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        std::fs::write(dir.join("lists/1.txt"), "||adnet.com^\n").unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, DEPLOY).unwrap();

        let rules = shared(RuleSet::default());
        let fetch = TestFetch::default();
        let lists = Arc::new(Lists::new(
            vec![ListConfig {
                id: 1,
                name: LIST_NAME.into(),
                url: LIST_1_URL.into(),
                enabled: true,
            }],
            vec![],
            dir.join("lists"),
            db.0.clone(),
            Arc::clone(&rules),
            fetch.clone(),
        ));
        let live = shared(live());
        let fake = Arc::new(State::default());
        let pipeline = Arc::new(Pipeline::new(
            Arc::clone(&rules),
            Arc::clone(&live),
            upstreams(&fake, Duration::from_millis(1)),
            300,
        ));
        let mut state = ApiState::new(
            setup.secret.map(|s| s.as_bytes().to_vec()),
            setup.store,
            setup.limits,
            setup.max_concurrent,
            Runtime {
                config_path,
                db_path: db.0.clone(),
                pipeline,
                lists,
                rules,
                live,
            },
        );
        state.stall = setup.stall;
        let state = Arc::new(state);
        Rig {
            fetch,
            app: router(Arc::clone(&state)),
            state,
            db,
            dir,
        }
    }

    impl Rig {
        /// Loads list 1 from its file into the running rule set.
        async fn load_lists(&self) {
            self.state.runtime.lists.load_last_good().await.unwrap();
        }

        async fn call(
            &self,
            method: Method,
            path: &str,
            auth: Option<&str>,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let mut req = Request::builder().method(method).uri(path);
            if let Some(a) = auth {
                req = req.header(header::AUTHORIZATION, a);
            }
            let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
            let resp = self
                .app
                .clone()
                .oneshot(req.body(body).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
            (status, value)
        }

        async fn query(&self, sql: &str, params: Value) -> (StatusCode, Value) {
            let body = json!({ "sql": sql, "params": params });
            self.call(Method::POST, "/integration/query", Some(AUTH), Some(body))
                .await
        }

        async fn action(&self, id: &str, params: Value) -> (StatusCode, Value) {
            let path = format!("/integration/actions/{id}");
            let body = json!({ "params": params });
            self.call(Method::POST, &path, Some(AUTH), Some(body)).await
        }

        /// An action that must answer 200; returns (ok, message).
        async fn act(&self, id: &str, params: Value) -> (bool, String) {
            let (status, body) = self.action(id, params).await;
            assert_eq!(status, StatusCode::OK, "{id}: {body}");
            let ok = body["ok"].as_bool().expect("ok is a bool");
            let message = body["message"].as_str().expect("message is text");
            (ok, message.to_string())
        }
    }

    #[tokio::test]
    async fn no_secret_means_503() {
        let r = rig(
            "nosecret",
            Setup {
                secret: None,
                ..Setup::default()
            },
        );
        let refused = json!({ "error": "api secret not configured" });
        for (method, path) in [
            (Method::GET, "/integration/manifest"),
            (Method::POST, "/integration/query"),
            (Method::POST, "/integration/actions/resume"),
            (Method::GET, "/nowhere"),
        ] {
            // Even with a header: there is nothing to compare it to.
            let got = r.call(method, path, Some(AUTH), None).await;
            assert_eq!(
                got,
                (StatusCode::SERVICE_UNAVAILABLE, refused.clone()),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn wrong_secret_401() {
        let r = rig("auth", Setup::default());
        let path = "/integration/manifest";
        for auth in [
            None,
            Some("Bearer wrong"),
            Some("Bearer s3cret-for-test"),
            Some("Bearer s3cret-for-tests2"),
            Some("Basic s3cret-for-tests"),
            Some("s3cret-for-tests"),
        ] {
            let (status, body) = r.call(Method::GET, path, auth, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{auth:?}");
            assert!(body["error"].is_string(), "{auth:?}: {body}");
        }
        let (status, _) = r.call(Method::GET, path, Some(AUTH), None).await;
        assert_eq!(status, StatusCode::OK);
        // Unknown routes are behind the same check.
        let (status, _) = r.call(Method::GET, "/nowhere", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = r.call(Method::GET, "/nowhere", Some(AUTH), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body["error"].is_string());
    }

    #[test]
    fn read_secret_trims_and_treats_empty_as_missing() {
        let dir = std::env::temp_dir().join(format!("lacuna-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        std::fs::write(&file, "  abc123\n").unwrap();
        assert_eq!(read_secret(&file), Some(b"abc123".to_vec()));
        std::fs::write(&file, " \n\t").unwrap();
        assert_eq!(read_secret(&file), None);
        assert_eq!(read_secret(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manifest_lists_views_and_dashboards() {
        let r = rig("manifest", Setup::default());
        let (status, m) = r
            .call(Method::GET, "/integration/manifest", Some(AUTH), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(m["name"], "lacuna");
        assert_eq!(m["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(m["schemaVersion"], 1);
        assert_eq!(m["maxConcurrent"], 2);
        let ids = |v: &Value, key: &str| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| x[key].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            ids(&m["schema"], "name"),
            ["queries", "hourly", "daily", "devices", "lists", "rules", "counters"]
        );
        assert!(m["schema"][0]["columns"][0]["type"].is_string());
        assert_eq!(ids(&m["variables"], "id"), ["client", "domain"]);
        assert_eq!(
            m["variables"][0]["optionsSql"],
            "SELECT client AS value, device AS label FROM devices ORDER BY label"
        );
        assert!(
            m["variables"][1].get("optionsSql").is_none(),
            "domain is free text"
        );

        let dashboards = m["dashboards"].as_array().unwrap();
        let got: Vec<(String, Vec<String>)> = dashboards
            .iter()
            .map(|d| (d["id"].as_str().unwrap().into(), ids(&d["panels"], "id")))
            .collect();
        let want = [
            (
                "overview",
                &[
                    "queries_over_time",
                    "blocked_pct",
                    "cache_hit_rate",
                    "log_dropped",
                    "upstream_latency",
                ][..],
            ),
            (
                "devices",
                &["by_device", "device_top_domains", "device_timeline"],
            ),
            ("domains", &["top_domains", "top_blocked", "domain_lookups"]),
            ("rules", &["lists_table", "top_rules", "never_hit"]),
            ("live", &["recent"]),
        ];
        let want: Vec<(String, Vec<String>)> = want
            .iter()
            .map(|(d, p)| (d.to_string(), p.iter().map(|s| s.to_string()).collect()))
            .collect();
        assert_eq!(got, want);
        assert_eq!(dashboards[2]["variables"], json!(["client", "domain"]));
        let recent = &dashboards[4]["panels"][0];
        assert_eq!(recent["kind"], "log");
        assert_eq!(recent["options"]["refreshSeconds"], 5);
        let kinds = ["stat", "timeseries", "bar", "table", "log"];
        for d in dashboards {
            for p in d["panels"].as_array().unwrap() {
                assert!(kinds.contains(&p["kind"].as_str().unwrap()), "{p}");
                let (x, w) = (&p["layout"]["x"], &p["layout"]["w"]);
                assert!(x.as_u64().unwrap() + w.as_u64().unwrap() <= 12, "{p}");
            }
        }

        assert_eq!(
            ids(&m["actions"], "id"),
            [
                "pause",
                "resume",
                "refresh_lists",
                "reload_config",
                "test_domain"
            ]
        );
        assert_eq!(
            m["actions"][0]["params"],
            json!([{ "id": "minutes", "label": "Minutes", "type": "int", "min": 1, "max": 1440 }])
        );
    }

    /// The manifest's columns are the views' columns, in order: they cannot drift.
    #[test]
    fn manifest_schema_matches_the_views() {
        let db = TempDb::new("schema");
        drop(Store::open(&db.0).unwrap());
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        for view in manifest(2).schema {
            let stmt = conn
                .prepare(&format!("SELECT * FROM {}", view.name))
                .unwrap();
            let names: Vec<&str> = view.columns.iter().map(|c| c.name).collect();
            let got: Vec<&str> = stmt.column_names().collect();
            assert_eq!(got, names, "{}", view.name);
        }
    }

    /// 2026-11-25T19:00:00Z.
    const END: i64 = 1_795_633_200_000;
    const MIN: i64 = 60_000;
    const HOUR: i64 = 3_600_000;
    const DAY: i64 = 24 * HOUR;
    const LAPTOP: &str = "192.168.0.10";

    /// 50 queries, one every 90 minutes up to END, across three clients and five kinds
    /// of answer, plus one hit of `||partial.test^` in MID_A's leading partial hour (and
    /// so its leading partial day). The rollups run as of six hours before END, so they hold most rows and the
    /// newest are raw only, as in production.
    fn seed(db: &Path) -> Vec<QueryRecord> {
        let clients = [LAPTOP, "192.168.0.20", "192.168.0.30"];
        let blocked = |ts, client, name| QueryRecord {
            outcome: Outcome::Blocked,
            reason: Reason::Rule,
            list_id: Some(1),
            rule: Some("||adnet.com^".into()),
            served_from: ServedFrom::Local,
            ..record(ts, client, name)
        };
        let mut records: Vec<QueryRecord> = (0..50)
            .map(|i| {
                let ts = END - (50 - i) * 90 * 60_000;
                let client = clients[i as usize % 3];
                match i % 5 {
                    0 => QueryRecord {
                        served_from: ServedFrom::Upstream,
                        upstream: Some("doh".into()),
                        latency_us: 20_000,
                        ..record(ts, client, "example.com")
                    },
                    1 => blocked(ts, client, "track.adnet.com"),
                    2 => QueryRecord {
                        outcome: Outcome::Rewritten,
                        served_from: ServedFrom::Local,
                        ..record(ts, client, "home.riddlelab.dev")
                    },
                    3 => blocked(ts, client, "adnet.com"),
                    _ => record(ts, client, "cdn.example.org"),
                }
            })
            .collect();
        records.push(QueryRecord {
            rule: Some("||partial.test^".into()),
            ..blocked(MID_A.from + 10 * MIN, LAPTOP, "partial.test")
        });
        let store = Store::open(db).unwrap();
        let mut conn = rusqlite::Connection::open(db).unwrap();
        let tx = conn.transaction().unwrap();
        writer::insert_batch(&tx, &records, Source::Lacuna).unwrap();
        tx.execute_batch(&format!(
            "UPDATE client_names SET name = 'laptop', origin = 'config' WHERE ip = '{LAPTOP}';
             INSERT INTO list_meta (id, name, url, enabled, parsed, skipped_json, fetched_at)
             VALUES (1, '{LIST_NAME}', '{LIST_1_URL}', 1, 2, '{{}}', {END});
             INSERT INTO rule_texts (list_id, text) VALUES (1, '||never.test^');"
        ))
        .unwrap();
        tx.commit().unwrap();
        rollup::roll_up(&store, END - 6 * HOUR).unwrap();
        records
    }

    struct Range {
        from: i64,
        to: i64,
    }

    /// Raw rows only.
    const SHORT: Range = Range {
        from: END - 24 * HOUR,
        to: END,
    };
    /// The rollups plus the raw tail; starts before the oldest row.
    const LONG: Range = Range {
        from: END - 7 * DAY,
        to: END + HOUR,
    };
    /// Start mid-hour and mid-IST-day, end in the past mid-day: partial buckets at both
    /// ends. MID_A ends after the daily rollup's edge, MID_B before it.
    const MID_A: Range = Range {
        from: END - 60 * HOUR - 17 * MIN,
        to: END - 20 * HOUR - 7 * MIN,
    };
    const MID_B: Range = Range {
        from: END - 70 * HOUR + 13 * MIN,
        to: END - 30 * HOUR - 7 * MIN,
    };
    /// Over 7 days (day buckets), ending mid-hour after the hourly rollup's edge.
    const WEEK_PLUS: Range = Range {
        from: END - 8 * DAY - 5 * HOUR - 13 * MIN,
        to: END - 2 * HOUR - 29 * MIN,
    };

    fn params(range: &Range, client: Option<&str>, domain: Option<&str>) -> Value {
        json!({ "from": range.from, "to": range.to, "client": client, "domain": domain })
    }

    fn column(frame: &Value, name: &str) -> Vec<Value> {
        let i = frame["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no column {name} in {frame}"));
        frame["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[i].clone())
            .collect()
    }

    fn sum(frame: &Value, name: &str) -> i64 {
        column(frame, name)
            .iter()
            .map(|v| v.as_i64().unwrap())
            .sum()
    }

    #[tokio::test]
    async fn every_default_panel_runs() {
        let r = rig("panels", Setup::default());
        let records = seed(&r.db.0);
        let m = manifest(2);
        for range in [&SHORT, &LONG, &MID_A, &MID_B, &WEEK_PLUS] {
            for client in [None, Some(LAPTOP)] {
                let picked: Vec<&QueryRecord> = records
                    .iter()
                    .filter(|q| q.ts_ms >= range.from && q.ts_ms < range.to)
                    .filter(|q| client.is_none_or(|c| q.client.to_string() == c))
                    .collect();
                let expected = picked.len() as i64;
                let blocked = picked
                    .iter()
                    .filter(|q| q.outcome == Outcome::Blocked)
                    .count() as i64;
                assert!(expected >= 5, "the seed covers the range: {expected}");
                let mut never: Vec<&str> = ["||adnet.com^", "||never.test^", "||partial.test^"]
                    .into_iter()
                    .filter(|rule| !picked.iter().any(|q| q.rule.as_deref() == Some(*rule)))
                    .collect();
                never.sort_unstable();

                let mut frames = BTreeMap::new();
                for d in &m.dashboards {
                    for p in &d.panels {
                        let (status, frame) = r.query(p.sql, params(range, client, None)).await;
                        let ctx = format!("{} from {} client {client:?}", p.id, range.from);
                        assert_eq!(status, StatusCode::OK, "{ctx}: {frame}");
                        let o = &p.options;
                        for role in [o.x, o.y, o.series, o.label].into_iter().flatten() {
                            column(&frame, role);
                        }
                        frames.insert(p.id, frame);
                    }
                }
                // Rollups plus raw rows at the edges count every query exactly once.
                let ctx = format!("from {} to {} client {client:?}", range.from, range.to);
                assert_eq!(sum(&frames["queries_over_time"], "n"), expected, "{ctx}");
                assert_eq!(sum(&frames["by_device"], "n"), expected, "{ctx}");
                assert_eq!(sum(&frames["device_timeline"], "n"), expected, "{ctx}");
                assert_eq!(sum(&frames["top_domains"], "n"), expected, "{ctx}");
                // Daily-based and hourly-based panels on one dashboard agree.
                assert_eq!(
                    sum(&frames["device_top_domains"], "n"),
                    sum(&frames["by_device"], "n"),
                    "{ctx}"
                );
                assert_eq!(sum(&frames["blocked_pct"], "queries"), expected, "{ctx}");
                let pct = (1000.0 * blocked as f64 / expected as f64).round() / 10.0;
                assert_eq!(column(&frames["blocked_pct"], "blocked_pct"), [json!(pct)]);
                assert_eq!(sum(&frames["top_blocked"], "n"), blocked, "{ctx}");
                assert_eq!(sum(&frames["top_rules"], "n"), blocked, "{ctx}");
                assert_eq!(column(&frames["log_dropped"], "dropped"), [json!(0)]);
                assert_eq!(column(&frames["cache_hit_rate"], "cache_hit_pct").len(), 1);
                assert!(!column(&frames["upstream_latency"], "avg_ms").is_empty());
                assert_eq!(column(&frames["lists_table"], "name"), [json!(LIST_NAME)]);
                let mut never_hit: Vec<String> = column(&frames["never_hit"], "rule")
                    .into_iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                never_hit.sort_unstable();
                assert_eq!(never_hit, never, "{ctx}");
                let recent = frames["recent"]["rows"].as_array().unwrap().len();
                assert_eq!(recent as i64, expected.min(200));
                if client.is_some() {
                    assert_eq!(column(&frames["by_device"], "device")[0], "laptop");
                }
            }
        }

        // The domain variable picks the domain and its subdomains, in any case.
        let lookups = m.dashboards[2].panels[2].sql;
        let (status, frame) = r
            .query(lookups, params(&SHORT, None, Some("AdNet.com")))
            .await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        let domains = column(&frame, "domain");
        let expected = records
            .iter()
            .filter(|q| q.ts_ms >= SHORT.from && q.ts_ms < SHORT.to)
            .filter(|q| q.name.ends_with("adnet.com"))
            .count();
        assert_eq!(domains.len(), expected);
        assert!(domains.contains(&json!("adnet.com")));
        assert!(domains.contains(&json!("track.adnet.com")));
        assert_eq!(column(&frame, "list")[0], LIST_NAME);

        // Once raw rows are gone (past retention), the leading partial day can only come
        // from the rollup: the whole day is counted, the one documented approximation.
        let cut = MID_A.from + 2 * HOUR;
        rusqlite::Connection::open(&r.db.0)
            .unwrap()
            .execute("DELETE FROM raw_queries WHERE ts < ?1", [cut])
            .unwrap();
        let day_start = MID_A.from - (MID_A.from + 19_800_000).rem_euclid(DAY);
        let whole_day = records
            .iter()
            .filter(|q| q.ts_ms >= day_start && q.ts_ms < MID_A.to)
            .count() as i64;
        let in_range = records
            .iter()
            .filter(|q| q.ts_ms >= MID_A.from && q.ts_ms < MID_A.to)
            .count() as i64;
        assert!(
            whole_day > in_range,
            "the seed has rows before MID_A.from that day"
        );
        let top = m.dashboards[2].panels[0].sql;
        let (status, frame) = r.query(top, params(&MID_A, None, None)).await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        assert_eq!(sum(&frame, "n"), whole_day);
    }

    /// Ruling R37: the raw-only aggregates read at most the last 7 days of the range and
    /// say so, since a 30-day raw scan timed out under DNS load.
    #[tokio::test]
    async fn raw_panels_read_at_most_seven_days() {
        let r = rig("raw7", Setup::default());
        let upstream = |ts: i64, ms: u32| QueryRecord {
            served_from: ServedFrom::Upstream,
            upstream: Some("doh".into()),
            latency_us: ms * 1000,
            ..record(ts, LAPTOP, "example.com")
        };
        // Old: three slow upstream answers. Recent: one cache hit, one fast upstream answer.
        let mut records: Vec<QueryRecord> =
            (0..3).map(|i| upstream(END - 20 * DAY + i, 900)).collect();
        records.push(record(END - DAY, LAPTOP, "example.com"));
        records.push(upstream(END - DAY + 1, 20));
        let mut conn = rusqlite::Connection::open(&r.db.0).unwrap();
        let tx = conn.transaction().unwrap();
        writer::insert_batch(&tx, &records, Source::Lacuna).unwrap();
        tx.commit().unwrap();

        let month = Range {
            from: END - 30 * DAY,
            to: END,
        };
        let m = manifest(2);
        let panel = |id: &str| {
            m.dashboards
                .iter()
                .flat_map(|d| &d.panels)
                .find(|p| p.id == id)
                .unwrap()
        };
        let (status, frame) = r
            .query(panel("cache_hit_rate").sql, params(&month, None, None))
            .await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        // 1 hit of 2 in the last week; the whole month would say 1 of 5.
        assert_eq!(column(&frame, "cache_hit_pct"), [json!(50.0)]);
        let (status, frame) = r
            .query(panel("upstream_latency").sql, params(&month, None, None))
            .await;
        assert_eq!(status, StatusCode::OK, "{frame}");
        assert_eq!(column(&frame, "avg_ms"), [json!(20.0)]);
        for id in ["cache_hit_rate", "upstream_latency"] {
            assert!(panel(id).title.ends_with("(last 7 days at most)"), "{id}");
        }
    }

    /// No default panel reads one of the big tables end to end, at either range length.
    #[test]
    fn default_panels_search_by_index() {
        let db = TempDb::new("plans");
        drop(Store::open(&db.0).unwrap());
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        // The steps of SQLite's plan for `sql`, with :from and :to bound if used.
        let plan = |sql: &str, range: &Range| -> Vec<String> {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            for (name, value) in [(":from", range.from), (":to", range.to)] {
                if let Some(i) = stmt.parameter_index(name).unwrap() {
                    stmt.raw_bind_parameter(i, value).unwrap();
                }
            }
            let mut rows = stmt.raw_query();
            let mut steps = Vec::new();
            while let Some(row) = rows.next().unwrap() {
                steps.push(row.get::<_, String>(3).unwrap());
            }
            steps
        };
        // raw_queries, hourly_counts and daily_counts, by their alias in views.sql.
        let scans_big = |steps: &[String]| {
            steps.iter().any(|step| {
                let table = step.strip_prefix("SCAN ").and_then(|t| t.split(' ').next());
                table.is_some_and(|t| ["q", "h", "dc"].contains(&t))
            })
        };
        // The check sees a scan when there is one.
        for sql in [
            "SELECT count(*) FROM queries",
            "SELECT sum(n) FROM hourly",
            "SELECT sum(n) FROM daily WHERE domain = 'x'",
        ] {
            assert!(scans_big(&plan(sql, &SHORT)), "{sql}");
        }
        for d in manifest(2).dashboards {
            for p in d.panels {
                for range in [&SHORT, &LONG] {
                    let steps = plan(p.sql, range);
                    assert!(!scans_big(&steps), "{}: {steps:#?}", p.id);
                }
            }
        }
    }

    #[tokio::test]
    async fn query_errors_are_400() {
        let _heavy = HEAVY_TEST.lock().await;
        let r = rig(
            "errors",
            Setup {
                limits: QueryLimits {
                    timeout: Duration::from_millis(200),
                    row_cap: 10_000,
                },
                ..Setup::default()
            },
        );
        let many = format!("SELECT {}", vec!["abs(1)"; 65].join(" + "));
        let big = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000)
                   SELECT hex(zeroblob(8000)) FROM n";
        let forever = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n)
                       SELECT count(*) FROM n";
        for (sql, params, wanted) in [
            ("DELETE FROM raw_queries", json!({}), "only reading"),
            ("SELECT 1; SELECT 2", json!({}), "one statement"),
            ("SELECT :nope", json!({}), ":nope"),
            (many.as_str(), json!({}), "more than 64 functions"),
            (big, json!({}), "8388608 bytes"),
            (forever, json!({}), "time limit of 200 ms"),
            ("SELEC 1", json!({}), "syntax error"),
            ("SELECT :x", json!({ "x": 1.5 }), "an integer, text or null"),
            ("SELECT :x", json!({ "x": [1] }), "an integer, text or null"),
        ] {
            let (status, body) = r.query(sql, params).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{sql}: {body}");
            let error = body["error"].as_str().unwrap_or_default();
            assert!(error.contains(wanted), "{sql}: {error}");
        }
        // A body with no sql, an unknown field, none at all, or one over 256 KiB.
        let huge = format!("SELECT 1 -- {}", "x".repeat(300 * 1024));
        for body in [
            Some(json!({ "params": {} })),
            Some(json!({ "sql": "SELECT 1", "extra": 1 })),
            None,
            Some(json!({ "sql": huge })),
        ] {
            let (status, got) = r
                .call(Method::POST, "/integration/query", Some(AUTH), body)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{got}");
            assert!(got["error"].is_string(), "{got}");
        }
    }

    /// The streamed body is exactly what serde would write for the `Frame`, also when it
    /// spans many chunks.
    #[tokio::test]
    async fn frame_streams_as_the_derive() {
        let r = rig("stream", Setup::default());
        let sql = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 3000)
                   SELECT x, 'row ' || x AS label, x / 2.0 AS half, NULL AS empty FROM n";
        let (status, body) = r.query(sql, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let direct = run_query(&r.db.0, sql, &BTreeMap::new(), &r.state.limits).unwrap();
        let mut want = serde_json::to_value(&direct).unwrap();
        // The only field that differs between two runs.
        want["elapsedMs"] = body["elapsedMs"].clone();
        assert_eq!(body, want);
        assert!(body["elapsedMs"].is_u64());
        assert_eq!(
            body["columns"][1],
            json!({ "name": "label", "type": "text" })
        );
        assert_eq!(body["rows"].as_array().unwrap().len(), 3000);

        let typed = json!({ "n": 7, "t": "x", "z": null });
        let (status, body) = r.query("SELECT :n + 1 AS a, :t AS b, :z AS c", typed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"], json!([[8, "x", null]]));
        assert_eq!(body["truncated"], false);
        let back: Frame = serde_json::from_value(body).unwrap();
        assert_eq!(back.columns[0].r#type, "integer");
        let p: ParamValue = serde_json::from_value(json!("x")).unwrap();
        assert_eq!(p, ParamValue::Text("x".into()));
    }

    #[tokio::test(start_paused = true)]
    async fn busy_gives_429_after_two_seconds() {
        let r = rig(
            "busy",
            Setup {
                max_concurrent: 1,
                ..Setup::default()
            },
        );
        let held = Arc::clone(&r.state.permits).acquire_owned().await.unwrap();
        let started = tokio::time::Instant::now();
        let got = r.query("SELECT 1", json!({})).await;
        assert_eq!(
            got,
            (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "busy" }))
        );
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        drop(held);
        assert_eq!(r.query("SELECT 1", json!({})).await.0, StatusCode::OK);
    }

    /// A client that hangs up, or stops reading, gives its query slot back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gone_or_stalled_clients_free_their_slot() {
        let _heavy = HEAVY_TEST.lock().await;
        let r = rig(
            "stall",
            Setup {
                max_concurrent: 1,
                stall: Duration::from_millis(300),
                ..Setup::default()
            },
        );
        // About 4.8 MB of JSON: far more chunks than are queued ahead of the client.
        let big = json!({ "sql": "WITH RECURSIVE n(x) AS
            (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 600)
            SELECT hex(zeroblob(4000)) FROM n" });
        let send = || {
            let req = Request::post("/integration/query")
                .header(header::AUTHORIZATION, AUTH)
                .body(Body::from(big.to_string()))
                .unwrap();
            r.app.clone().oneshot(req)
        };

        let unread = send().await.unwrap();
        assert_eq!(unread.status(), StatusCode::OK);
        let started = Instant::now();
        assert_eq!(r.query("SELECT 1", json!({})).await.0, StatusCode::OK);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(250), "{waited:?}");
        drop(unread);

        let dropped = send().await.unwrap();
        drop(dropped);
        let started = Instant::now();
        assert_eq!(r.query("SELECT 1", json!({})).await.0, StatusCode::OK);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    /// Ruling R27: with no log store, queries say why; everything else keeps working.
    #[tokio::test]
    async fn store_unavailable_gives_503_on_query_only() {
        let r = rig(
            "nostore",
            Setup {
                store: Err("disk gone".into()),
                ..Setup::default()
            },
        );
        let got = r.query("SELECT 1", json!({})).await;
        assert_eq!(
            got,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": "log store unavailable: disk gone" })
            )
        );
        let (status, _) = r
            .call(Method::GET, "/integration/manifest", Some(AUTH), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(r.act("resume", json!({})).await.0);
    }

    #[tokio::test]
    async fn test_domain_action_names_rule() {
        let r = rig("testdomain", Setup::default());
        r.load_lists().await;
        let test = |name: &'static str| r.act("test_domain", json!({ "name": name }));
        let blocked = format!("blocked by ||adnet.com^ ({LIST_NAME})");
        assert_eq!(test("adnet.com").await, (true, blocked.clone()));
        assert_eq!(test("Ads.AdNet.com.").await, (true, blocked.clone()));
        assert_eq!(test("example.org").await, (true, "allowed".into()));
        assert_eq!(
            test("home.riddlelab.dev").await,
            (true, "rewritten to 192.168.0.107".into())
        );
        let (ok, message) = test("version.bind").await;
        assert!(ok && message.starts_with("refused"), "{message}");
        for bad in [json!({}), json!({ "name": "" }), json!({ "name": 5 })] {
            let (status, body) = r.action("test_domain", bad).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["ok"], false, "{body}");
        }

        // Paused: the answer says so, and what the rules would do.
        r.act("pause", json!({ "minutes": 5 })).await;
        let (ok, message) = test("adnet.com").await;
        assert!(ok);
        assert!(
            message.contains("paused") && message.contains(&blocked),
            "{message}"
        );
    }

    #[tokio::test]
    async fn pause_validates_minutes() {
        let r = rig("pause", Setup::default());
        let pipeline = &r.state.runtime.pipeline;
        for bad in [
            json!(0),
            json!(1441),
            json!(-5),
            json!(2.5),
            json!("10"),
            Value::Null,
        ] {
            let (ok, message) = r.act("pause", json!({ "minutes": bad })).await;
            assert!(!ok, "{bad}");
            assert!(message.contains("1 to 1440"), "{message}");
            assert!(!pipeline.is_paused_now());
        }
        assert!(!r.act("pause", json!({})).await.0);
        assert!(r.act("pause", json!({ "minutes": 1 })).await.0);
        assert!(pipeline.is_paused_now());
        assert_eq!(
            r.act("pause", json!({ "minutes": 1440 })).await,
            (true, "blocking paused for 1440 minutes".into())
        );
        assert_eq!(
            r.act("resume", json!({})).await,
            (true, "blocking resumed".into())
        );
        assert!(!pipeline.is_paused_now());
    }

    #[tokio::test]
    async fn reload_with_bad_config_keeps_old() {
        let r = rig("reload", Setup::default());
        r.load_lists().await;
        let path = &r.state.runtime.config_path;
        let rewrites = || current(&r.state.runtime.live).rewrites.len();
        assert_eq!(rewrites(), 2);

        // Not TOML, then TOML that fails validation: refused, nothing changes.
        for broken in [
            "this is not toml".to_string(),
            DEPLOY.replace("race_timeout_ms = 1000", "race_timeout_ms = 0"),
        ] {
            std::fs::write(path, &broken).unwrap();
            let (ok, message) = r.act("reload_config", json!({})).await;
            assert!(!ok);
            assert!(message.contains("config.toml"), "{message}");
            assert_eq!(rewrites(), 2);
            let (_, verdict) = r.act("test_domain", json!({ "name": "adnet.com" })).await;
            assert!(verdict.starts_with("blocked"), "{verdict}");
        }

        // A good config applies everything a reload covers.
        let good = DEPLOY
            .replace("user_rules = []", "user_rules = [\"@@||adnet.com^\"]")
            .replace(
                "[devices]\n",
                "[devices]\n\"192.168.0.99\" = \"tv\"\n\n\
                 [[rewrites]]\nname = \"nas.lan\"\na = \"192.168.0.50\"\n",
            );
        assert!(
            good.contains("nas.lan") && good.contains("@@"),
            "fixture text moved"
        );
        std::fs::write(path, &good).unwrap();
        let (ok, message) = r.act("reload_config", json!({})).await;
        assert!(ok, "{message}");
        // Everything outside LiveConfig, the lists and the device names is read once at start.
        for needs_restart in [
            "[upstreams]",
            "dns.listen",
            "dns.max_inflight",
            "dns.router",
            "[api]",
            "[store]",
        ] {
            assert!(message.contains(needs_restart), "{needs_restart}: {message}");
        }
        assert_eq!(rewrites(), 3);
        let (_, verdict) = r.act("test_domain", json!({ "name": "nas.lan" })).await;
        assert_eq!(verdict, "rewritten to 192.168.0.50");
        let (_, verdict) = r.act("test_domain", json!({ "name": "adnet.com" })).await;
        assert_eq!(verdict, "allowed by @@||adnet.com^ (user rules)");
        let conn = rusqlite::Connection::open(&r.db.0).unwrap();
        let name: String = conn
            .query_row(
                "SELECT device FROM devices WHERE client = '192.168.0.99'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "tv");
    }

    /// Ruling R29: a reload that adds a list, or moves one to a new URL, fetches it in
    /// the background instead of waiting for the daily refresh.
    #[tokio::test]
    async fn reload_fetches_new_and_moved_lists() {
        let r = rig("newlists", Setup::default());
        r.load_lists().await;
        let new_url = "https://lists.test/3.txt";
        r.fetch.serve(new_url, "||newlist.test^\n");
        let added = DEPLOY.replacen(
            "[[rewrites]]",
            &format!(
                "[[lists]]\nid = 3\nname = \"New\"\nurl = \"{new_url}\"\nenabled = true\n\n\
                 [[rewrites]]"
            ),
            1,
        );
        assert_ne!(added, DEPLOY);
        let path = &r.state.runtime.config_path;
        std::fs::write(path, &added).unwrap();
        let (ok, message) = r.act("reload_config", json!({})).await;
        assert!(ok, "{message}");
        assert!(message.contains("refreshing 1 new list"), "{message}");
        let verdict = || r.act("test_domain", json!({ "name": "newlist.test" }));
        let mut waited = 0;
        while verdict().await.1 == "allowed" {
            assert!(waited < 200, "the new list was not fetched");
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        assert_eq!(verdict().await.1, "blocked by ||newlist.test^ (New)");

        // Reloading the same file again fetches nothing.
        let (ok, message) = r.act("reload_config", json!({})).await;
        assert!(ok && !message.contains("refreshing"), "{message}");

        // List 1 moves: its old body is dropped and the new URL is fetched.
        let moved_url = "https://lists.test/1-moved.txt";
        r.fetch.serve(moved_url, "||moved.test^\n");
        std::fs::write(path, added.replace(LIST_1_URL, moved_url)).unwrap();
        let (ok, message) = r.act("reload_config", json!({})).await;
        assert!(ok && message.contains("refreshing 1 new list"), "{message}");
        let moved = || r.act("test_domain", json!({ "name": "moved.test" }));
        let mut waited = 0;
        while moved().await.1 == "allowed" {
            assert!(waited < 200, "the moved list was not fetched");
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        let (_, old) = r.act("test_domain", json!({ "name": "adnet.com" })).await;
        assert_eq!(old, "allowed");
    }

    #[tokio::test]
    async fn every_manifest_action_is_handled() {
        let r = rig("actions", Setup::default());
        for a in ActionId::ALL {
            let (status, body) = r.action(a.id(), json!({})).await;
            assert_eq!(status, StatusCode::OK, "{}: {body}", a.id());
        }
        let (status, body) = r.action("format_disk", json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body["error"].is_string());
        // No body at all is the same as no params.
        let (status, _) = r
            .call(
                Method::POST,
                "/integration/actions/resume",
                Some(AUTH),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        // A refresh where every fetch fails says so.
        let (ok, message) = r.act("refresh_lists", json!({})).await;
        assert!(!ok);
        assert!(message.contains("offline in tests"), "{message}");
    }

    /// Review Focus 5: a query at its time limit runs on a blocking thread and never
    /// holds up DNS, which answers on the async workers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_answers_during_slow_query() {
        let _heavy = HEAVY_TEST.lock().await;
        let r = rig(
            "slow",
            Setup {
                limits: QueryLimits {
                    timeout: Duration::from_secs(3),
                    row_cap: 10_000,
                },
                ..Setup::default()
            },
        );
        let listeners = Listeners::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let dns = listeners.local_addr().unwrap();
        tokio::spawn(server::run(
            Arc::clone(&r.state.runtime.pipeline),
            listeners,
            Arc::new(NoopSink),
        ));
        let api = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_addr = api.local_addr().unwrap();
        tokio::spawn(serve(api, Arc::clone(&r.state)));

        let body = json!({
            "sql": "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n)
                    SELECT count(*) FROM n",
            "params": {}
        })
        .to_string();
        let slow = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(api_addr).await.unwrap();
            let req = format!(
                "POST /integration/query HTTP/1.1\r\nHost: lacuna\r\nAuthorization: {AUTH}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let name = Name::from_ascii("home.riddlelab.dev.").unwrap();
        let ups = UdpUpstream::with_timeout(dns, Duration::from_secs(1));
        for i in 0..20 {
            let mut q = Message::new(i, MessageType::Query, OpCode::Query);
            q.metadata.recursion_desired = true;
            q.add_query(Query::query(name.clone(), RecordType::A));
            let started = Instant::now();
            let answer = ups.query(&q).await.unwrap();
            let took = started.elapsed();
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert!(took < Duration::from_millis(50), "query {i} took {took:?}");
        }
        assert!(!slow.is_finished(), "the slow query ran throughout");
        let response = slow.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("time limit"), "{response}");
    }

    /// Ruling 4: the process's peak memory with two worst-case queries streaming out at
    /// once. Run alone, so no other test shares the process:
    /// `cargo test -- --ignored --test-threads=1 two_worst_queries_peak_rss --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn two_worst_queries_peak_rss() {
        let _heavy = HEAVY_TEST.lock().await;
        fn status_kib(key: &str) -> i64 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            status
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                .unwrap()
        }
        let r = rig("rss", Setup::default());
        // Text values just under the 8 MiB result budget; then many small values.
        let wide = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 520)
                    SELECT hex(zeroblob(8000)) || x AS v FROM n"
            .to_string();
        let many = format!(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 10000)
             SELECT {} FROM n",
            (0..25)
                .map(|i| format!("x + {i} AS c{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for (label, sql) in [("wide", wide), ("many", many)] {
            // Warm up once, then reset the high-water mark (5 to clear_refs).
            assert_eq!(r.query(&sql, json!({})).await.0, StatusCode::OK);
            let base = status_kib("VmRSS:");
            std::fs::write("/proc/self/clear_refs", "5").unwrap();
            let run = || async {
                let body = json!({ "sql": sql, "params": {} });
                let req = Request::post("/integration/query")
                    .header(header::AUTHORIZATION, AUTH)
                    .body(Body::from(body.to_string()))
                    .unwrap();
                let resp = r.app.clone().oneshot(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                // Read as a client does, chunk by chunk, keeping only a count.
                let mut body = resp.into_body();
                let mut n = 0;
                while let Some(frame) =
                    std::future::poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut body), cx))
                        .await
                {
                    n += frame.unwrap().into_data().map_or(0, |d| d.len());
                }
                n
            };
            let (a, b) = tokio::join!(run(), run());
            let peak = status_kib("VmHWM:");
            println!(
                "{label}: {a} + {b} bytes of JSON; RSS before {base} KiB, \
                 peak {peak} KiB, extra {} KiB",
                peak - base
            );
        }
    }
}
