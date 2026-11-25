//! Runs one user-written SQL query against the query log, read-only.
//!
//! The SQL comes from Sonder's dashboards, so it is treated as hostile. Every layer below
//! would stop a write on its own; they are stacked so that one SQLite surprise is not a
//! hole:
//! * the file is opened read-only, and `query_only` refuses writes on top of that;
//! * an authorizer, consulted while SQLite compiles the statement, allows only reading
//!   (SELECT, column reads, functions, recursive CTEs) and refuses every other action:
//!   writes, PRAGMA, ATTACH, transactions, temp objects, `load_extension`;
//! * only one statement runs; anything but whitespace or comments after it is refused;
//! * limits cap the SQL length, the size of any one value, and attached databases at 0;
//! * a progress handler stops the query at its deadline, and the row cap bounds the
//!   result.
//!
//! Each query gets its own connection, closed when it returns, so nothing it sets can
//! leak into the next one, and the log writer's connection is never touched.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Batch, Connection, ErrorCode, OpenFlags, Rows, Statement, ToSql};
use serde_json::Value;

/// The progress handler runs every this many SQLite VM instructions (microseconds each).
const PROGRESS_STEPS: i32 = 1000;
const MAX_SQL_BYTES: i32 = 100_000;
/// The largest string or blob a query may build or read. A single `randomblob(1e9)` is
/// one VM instruction, so the deadline cannot stop it; this limit can. Log values are
/// short (names, addresses, small JSON), so 1 MB is far above any real one.
const MAX_VALUE_BYTES: i32 = 1_000_000;
/// Set before the authorizer is installed, which would refuse them. cache_size is
/// negative KiB: 2 MB. temp_store FILE sends sort and temp-table spills to SQLITE_TMPDIR
/// on the volume, not to memory charged to the container.
const READ_PRAGMAS: &str =
    "PRAGMA query_only = ON; PRAGMA cache_size = -2048; PRAGMA temp_store = FILE;";
/// Functions refused even inside a SELECT: they load code or touch files. Bundled SQLite
/// has no file functions, but naming them keeps that true if the build ever changes.
const DENIED_FUNCTIONS: &[&str] = &[
    "load_extension",
    "readfile",
    "writefile",
    "edit",
    "fts3_tokenizer",
];

/// How long a query may run and how many rows it may return.
#[derive(Debug, Clone, Copy)]
pub struct QueryLimits {
    pub timeout: Duration,
    pub row_cap: usize,
}

/// A value for a `:name` parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    Int(i64),
    Text(String),
    Null,
}

impl ToSql for ParamValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            ParamValue::Int(n) => ToSqlOutput::from(*n),
            ParamValue::Text(s) => ToSqlOutput::from(s.as_str()),
            ParamValue::Null => ToSqlOutput::from(rusqlite::types::Null),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    /// "integer", "real", "text" or "null": the type of the first non-null value in the
    /// column (a declared type says nothing for a view's computed columns). Blobs are
    /// sent as text, so they count as "text".
    pub r#type: String,
}

/// A query result, row by row in column order.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QueryError {
    /// The statement does something other than read; the text names what.
    NotReadOnly(String),
    MultipleStatements,
    UnknownParam(String),
    Timeout,
    Sql(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::NotReadOnly(what) => write!(f, "only reading is allowed, refused: {what}"),
            QueryError::MultipleStatements => f.write_str("only one statement is allowed"),
            QueryError::UnknownParam(name) => write!(f, "parameter :{name} has no value"),
            QueryError::Timeout => f.write_str("query stopped at the time limit"),
            QueryError::Sql(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for QueryError {}

/// Runs `sql` with `params` bound to its `:name` parameters. Blocking: async callers run
/// it on a blocking thread.
pub fn run_query(
    db_path: &Path,
    sql: &str,
    params: &BTreeMap<String, ParamValue>,
    limits: &QueryLimits,
) -> Result<Frame, QueryError> {
    let started = Instant::now();
    let denied = Arc::new(Mutex::new(None));
    let conn = open(db_path, started + limits.timeout, Arc::clone(&denied))
        .map_err(|e| classify(e, &denied))?;
    let frame = execute(&conn, sql, params, limits.row_cap).map_err(|e| match e {
        Failure::Query(q) => q,
        Failure::Sqlite(e) => classify(e, &denied),
    })?;
    Ok(Frame {
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        ..frame
    })
}

/// A read-only connection with every guard installed. `denied` receives a description
/// of the first action the authorizer refuses.
fn open(
    db_path: &Path,
    deadline: Instant,
    denied: Arc<Mutex<Option<String>>>,
) -> rusqlite::Result<Connection> {
    // Spelled out rather than `OpenFlags::default()`, which would add READ_WRITE, CREATE
    // and URI. NO_MUTEX: the connection never leaves this thread.
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut conn = Connection::open_with_flags(db_path, flags)?;
    // A WAL reader waits only in rare moments (the writer's checkpoint restarting the
    // log); never past the query's own budget.
    conn.busy_timeout(deadline.saturating_duration_since(Instant::now()))?;
    conn.execute_batch(READ_PRAGMAS)?;
    conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_BYTES)?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)?;
    conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        authorize(ctx.action, &denied)
    }))?;
    // Returning true interrupts the running statement with SQLITE_INTERRUPT.
    conn.progress_handler(PROGRESS_STEPS, Some(move || Instant::now() >= deadline))?;
    Ok(conn)
}

fn authorize(action: AuthAction<'_>, denied: &Mutex<Option<String>>) -> Authorization {
    let allowed = match action {
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => true,
        AuthAction::Function { function_name } => !DENIED_FUNCTIONS
            .iter()
            .any(|f| f.eq_ignore_ascii_case(function_name)),
        _ => false,
    };
    if allowed {
        return Authorization::Allow;
    }
    if let Ok(mut first) = denied.lock() {
        first.get_or_insert_with(|| format!("{action:?}"));
    }
    Authorization::Deny
}

/// A query refused by this module's own checks, or an error from SQLite.
enum Failure {
    Query(QueryError),
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for Failure {
    fn from(e: rusqlite::Error) -> Failure {
        Failure::Sqlite(e)
    }
}

impl From<QueryError> for Failure {
    fn from(e: QueryError) -> Failure {
        Failure::Query(e)
    }
}

fn execute(
    conn: &Connection,
    sql: &str,
    params: &BTreeMap<String, ParamValue>,
    row_cap: usize,
) -> Result<Frame, Failure> {
    let mut stmt = single_statement(conn, sql)?;
    // SQLite's own verdict, a last check behind the authorizer.
    if !stmt.readonly() {
        return Err(QueryError::NotReadOnly("a statement that writes".into()).into());
    }
    bind(&mut stmt, params)?;
    let columns: Vec<String> = stmt.column_names().map(String::from).collect();
    let (rows, types, truncated) = fetch(stmt.raw_query(), columns.len(), row_cap)?;
    Ok(Frame {
        columns: columns
            .into_iter()
            .zip(types)
            .map(|(name, t)| Column {
                name,
                r#type: t.unwrap_or("null").to_string(),
            })
            .collect(),
        rows,
        truncated,
        elapsed_ms: 0,
    })
}

/// Compiles the first statement. Whatever follows it must compile to nothing, that is be
/// only whitespace and comments; a second statement is refused even when it would
/// itself be refused for another reason. `Batch` compiles one statement at a time and
/// never runs any.
fn single_statement<'c>(conn: &'c Connection, sql: &str) -> Result<Statement<'c>, Failure> {
    let mut batch = Batch::new(conn, sql);
    let Some(stmt) = batch.next()? else {
        return Err(QueryError::Sql("the query is empty".into()).into());
    };
    match batch.next() {
        Ok(None) => Ok(stmt),
        Ok(Some(_)) | Err(_) => Err(QueryError::MultipleStatements.into()),
    }
}

/// Binds each `:name` in the SQL from `params`. One parameter style keeps dashboards
/// uniform, so `?`, `?NNN`, `@name` and `$name` are refused.
fn bind(stmt: &mut Statement<'_>, params: &BTreeMap<String, ParamValue>) -> Result<(), Failure> {
    // SQLite numbers parameters from 1; a name used twice shares one number.
    for i in 1..=stmt.parameter_count() {
        let name = match stmt.parameter_name(i) {
            Some(n) if n.starts_with(':') => n[1..].to_string(),
            other => {
                let shown = other.unwrap_or("?");
                return Err(QueryError::Sql(format!(
                    "parameter {shown}: use the :name style for parameters"
                ))
                .into());
            }
        };
        let value = params.get(&name).ok_or(QueryError::UnknownParam(name))?;
        stmt.raw_bind_parameter(i, value)?;
    }
    Ok(())
}

type Fetched = (Vec<Vec<Value>>, Vec<Option<&'static str>>, bool);

/// Reads up to `row_cap` rows; one more row present means the result was truncated.
fn fetch(mut rows: Rows<'_>, width: usize, row_cap: usize) -> rusqlite::Result<Fetched> {
    let mut out = Vec::new();
    let mut types: Vec<Option<&'static str>> = vec![None; width];
    while let Some(row) = rows.next()? {
        if out.len() == row_cap {
            return Ok((out, types, true));
        }
        let mut values = Vec::with_capacity(width);
        for (i, t) in types.iter_mut().enumerate() {
            let v = row.get_ref(i)?;
            if t.is_none() {
                *t = type_name(v);
            }
            values.push(to_json(v));
        }
        out.push(values);
    }
    Ok((out, types, false))
}

fn type_name(v: ValueRef<'_>) -> Option<&'static str> {
    match v {
        ValueRef::Null => None,
        ValueRef::Integer(_) => Some("integer"),
        ValueRef::Real(_) => Some("real"),
        ValueRef::Text(_) | ValueRef::Blob(_) => Some("text"),
    }
}

fn to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(n) => Value::from(n),
        // JSON has no NaN or infinity: those become null.
        ValueRef::Real(x) => serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Value::String(format!("<blob {} bytes>", bytes.len())),
    }
}

/// Names a SQLite error for the caller: refused by the authorizer or by read-only mode,
/// stopped at the deadline, or an ordinary SQL error. The authorizer's own record comes
/// first: a refused function, unlike a refused statement, fails with a plain SQLITE_ERROR.
fn classify(e: rusqlite::Error, denied: &Mutex<Option<String>>) -> QueryError {
    if let Some(what) = denied.lock().ok().and_then(|mut d| d.take()) {
        return QueryError::NotReadOnly(what);
    }
    match e.sqlite_error_code() {
        Some(ErrorCode::AuthorizationForStatementDenied | ErrorCode::ReadOnly) => {
            QueryError::NotReadOnly(e.to_string())
        }
        Some(ErrorCode::OperationInterrupted) => QueryError::Timeout,
        _ => QueryError::Sql(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::TempDb;
    use crate::store::Store;
    use serde_json::json;

    const ROWS: i64 = 10;

    /// A real log file with ROWS queries, and an open write connection beside it, as in
    /// production (the writer keeps the WAL files in place).
    struct Fixture {
        writer: Connection,
        db: TempDb,
    }

    impl Fixture {
        fn new() -> Fixture {
            let db = TempDb::new("readonly");
            drop(Store::open(&db.0).unwrap());
            let writer = Connection::open(&db.0).unwrap();
            writer
                .execute_batch(
                    "INSERT INTO domain_names (id, name) VALUES (1, 'example.com');
                     INSERT INTO client_names (ip, name, origin, first_seen, last_seen)
                     VALUES ('192.168.0.10', 'laptop', 'config', 0, 0);",
                )
                .unwrap();
            for i in 0..ROWS {
                writer
                    .execute(
                        "INSERT INTO raw_queries (ts, client, domain_id, qtype, rcode, outcome,
                             reason, served_from, latency_us, answers, source)
                         VALUES (?1, '192.168.0.10', 1, 1, 0, 0, 0, 0, 1500, '', 0)",
                        [i * 1000],
                    )
                    .unwrap();
            }
            Fixture { writer, db }
        }

        fn raw_rows(&self) -> i64 {
            self.writer
                .query_row("SELECT count(*) FROM raw_queries", [], |r| r.get(0))
                .unwrap()
        }

        fn run(&self, sql: &str) -> Result<Frame, QueryError> {
            self.run_with(sql, &BTreeMap::new(), limits(100))
        }

        fn run_with(
            &self,
            sql: &str,
            params: &BTreeMap<String, ParamValue>,
            limits: QueryLimits,
        ) -> Result<Frame, QueryError> {
            run_query(&self.db.0, sql, params, &limits)
        }

        /// Asserts that `sql` is refused as a write and changed nothing.
        fn assert_refused(&self, sql: &str) {
            let r = self.run(sql);
            assert!(matches!(r, Err(QueryError::NotReadOnly(_))), "{sql}: {r:?}");
            assert_eq!(self.raw_rows(), ROWS, "{sql} changed the log");
        }
    }

    fn limits(row_cap: usize) -> QueryLimits {
        QueryLimits {
            timeout: Duration::from_secs(5),
            row_cap,
        }
    }

    fn params(pairs: &[(&str, ParamValue)]) -> BTreeMap<String, ParamValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn types(frame: &Frame) -> Vec<&str> {
        frame.columns.iter().map(|c| c.r#type.as_str()).collect()
    }

    #[test]
    fn select_returns_frame() {
        let f = Fixture::new();
        let frame = f
            .run(
                "SELECT ts, device, latency_ms, NULL AS empty, 1e999 AS inf
                 FROM queries ORDER BY ts LIMIT 2",
            )
            .unwrap();
        let names: Vec<&str> = frame.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["ts", "device", "latency_ms", "empty", "inf"]);
        assert_eq!(types(&frame), ["integer", "text", "real", "null", "real"]);
        // JSON has no infinity, so an infinite real is null.
        assert_eq!(
            frame.rows,
            [
                vec![
                    json!(0),
                    json!("laptop"),
                    json!(1.5),
                    Value::Null,
                    Value::Null
                ],
                vec![
                    json!(1000),
                    json!("laptop"),
                    json!(1.5),
                    Value::Null,
                    Value::Null
                ],
            ]
        );
        assert!(!frame.truncated);
    }

    #[test]
    fn column_type_is_the_first_non_null_value() {
        let f = Fixture::new();
        let frame = f
            .run("SELECT NULL AS x UNION ALL SELECT 'a' UNION ALL SELECT 2")
            .unwrap();
        assert_eq!(types(&frame), ["text"]);
        assert_eq!(frame.rows, [[Value::Null], [json!("a")], [json!(2)]]);
    }

    #[test]
    fn view_and_internal_table_both_work() {
        let f = Fixture::new();
        for sql in [
            "SELECT count(*) FROM queries",
            "SELECT count(*) FROM raw_queries",
        ] {
            assert_eq!(f.run(sql).unwrap().rows, [[json!(ROWS)]], "{sql}");
        }
    }

    #[test]
    fn blob_renders_as_its_size() {
        let f = Fixture::new();
        let frame = f.run("SELECT zeroblob(5) AS b").unwrap();
        assert_eq!(frame.rows, [[json!("<blob 5 bytes>")]]);
        assert_eq!(types(&frame), ["text"]);
    }

    #[test]
    fn params_are_bound_not_pasted() {
        let f = Fixture::new();
        let sql = "SELECT ts FROM queries WHERE client = :client";
        let injected = params(&[("client", ParamValue::Text("x' OR 1=1 --".into()))]);
        assert_eq!(
            f.run_with(sql, &injected, limits(100)).unwrap().rows.len(),
            0
        );

        // The same SQL with a real value finds the rows; params it does not use are ignored.
        let real = params(&[
            ("client", ParamValue::Text("192.168.0.10".into())),
            ("unused", ParamValue::Int(1)),
        ]);
        let n = f.run_with(sql, &real, limits(100)).unwrap().rows.len();
        assert_eq!(n as i64, ROWS);

        let typed = params(&[("n", ParamValue::Int(7)), ("z", ParamValue::Null)]);
        let frame = f
            .run_with("SELECT :n + 1, :z IS NULL", &typed, limits(100))
            .unwrap();
        assert_eq!(frame.rows, [[json!(8), json!(1)]]);
    }

    #[test]
    fn unknown_param_rejected() {
        let f = Fixture::new();
        let r = f.run("SELECT ts FROM queries WHERE client = :client");
        assert_eq!(r, Err(QueryError::UnknownParam("client".into())));
    }

    #[test]
    fn only_colon_params_are_accepted() {
        let f = Fixture::new();
        let p = params(&[("1", ParamValue::Int(1)), ("c", ParamValue::Int(1))]);
        for sql in ["SELECT ?1", "SELECT ?", "SELECT @c", "SELECT $c"] {
            match f.run_with(sql, &p, limits(100)) {
                Err(QueryError::Sql(msg)) => assert!(msg.contains(":name"), "{sql}: {msg}"),
                other => panic!("{sql}: {other:?}"),
            }
        }
    }

    #[test]
    fn insert_refused() {
        let f = Fixture::new();
        f.assert_refused("INSERT INTO raw_queries SELECT * FROM raw_queries");
        f.assert_refused("INSERT INTO counter_values (name, value) VALUES ('x', 1)");
    }

    #[test]
    fn update_refused() {
        Fixture::new().assert_refused("UPDATE raw_queries SET client = 'x'");
    }

    #[test]
    fn delete_refused() {
        Fixture::new().assert_refused("DELETE FROM raw_queries");
    }

    #[test]
    fn attach_refused() {
        let f = Fixture::new();
        let other = TempDb::new("attached");
        f.assert_refused(&format!("ATTACH DATABASE '{}' AS x", other.0.display()));
        assert!(!other.0.exists());
    }

    #[test]
    fn vacuum_into_refused() {
        // VACUUM INTO works on a read-only database and writes a file: it must not get far.
        let f = Fixture::new();
        let copy = TempDb::new("vacuum-copy");
        let r = f.run(&format!("VACUUM INTO '{}'", copy.0.display()));
        assert!(r.is_err(), "{r:?}");
        assert!(!copy.0.exists());
    }

    #[test]
    fn pragma_write_refused() {
        Fixture::new().assert_refused("PRAGMA writable_schema = 1");
    }

    #[test]
    fn pragma_read_refused() {
        Fixture::new().assert_refused("PRAGMA table_info(queries)");
    }

    #[test]
    fn begin_refused() {
        Fixture::new().assert_refused("BEGIN");
    }

    #[test]
    fn create_temp_table_refused() {
        Fixture::new().assert_refused("CREATE TEMP TABLE t (x)");
    }

    #[test]
    fn load_extension_refused() {
        let f = Fixture::new();
        f.assert_refused("SELECT load_extension('/nonexistent.so')");
        f.assert_refused("SELECT fts3_tokenizer('simple')");
    }

    #[test]
    fn second_statement_refused() {
        let f = Fixture::new();
        let r = f.run("SELECT 1; DELETE FROM raw_queries");
        assert_eq!(r, Err(QueryError::MultipleStatements));
        assert_eq!(f.raw_rows(), ROWS);
        let r = f.run("SELECT 1; SELECT 2");
        assert_eq!(r, Err(QueryError::MultipleStatements));
    }

    #[test]
    fn trailing_comments_accepted() {
        let f = Fixture::new();
        for sql in [
            "SELECT 1 -- done",
            "SELECT 1; -- done",
            "SELECT 1 /* a */ ; /* b */\n  -- c\n",
        ] {
            assert_eq!(f.run(sql).unwrap().rows, [[json!(1)]], "{sql}");
        }
    }

    #[test]
    fn runaway_query_is_stopped() {
        let f = Fixture::new();
        let forever = "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n)
                       SELECT count(*) FROM n";
        let limits = QueryLimits {
            timeout: Duration::from_millis(200),
            row_cap: 100,
        };
        let started = Instant::now();
        let r = f.run_with(forever, &BTreeMap::new(), limits);
        assert_eq!(r, Err(QueryError::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn row_cap_truncates() {
        let f = Fixture::new();
        let none = BTreeMap::new();
        let frame = f
            .run_with("SELECT ts FROM queries", &none, limits(3))
            .unwrap();
        assert_eq!(frame.rows.len(), 3);
        assert!(frame.truncated);

        // Exactly the cap is not truncated.
        let frame = f
            .run_with("SELECT ts FROM queries", &none, limits(ROWS as usize))
            .unwrap();
        assert_eq!(frame.rows.len() as i64, ROWS);
        assert!(!frame.truncated);
    }

    #[test]
    fn oversized_values_refused() {
        // One huge value would be charged to the container's 96 MB in a single VM step,
        // before the progress handler can stop it.
        let f = Fixture::new();
        let r = f.run("SELECT length(randomblob(2000000))");
        assert!(matches!(r, Err(QueryError::Sql(_))), "{r:?}");

        let long = format!("SELECT 1 -- {}", "x".repeat(100_000));
        let r = f.run(&long);
        assert!(matches!(r, Err(QueryError::Sql(_))), "{r:?}");
    }
}
