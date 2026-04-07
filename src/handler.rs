use crate::auth::METADATA_USER_ID;
use crate::error::ProxyError;
use crate::pool::ConnectionManager;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{stream, Sink, Stream, TryStreamExt};
use pgwire::api::portal::Portal;
use pgwire::api::query::ExtendedQueryHandler;
use pgwire::api::{ClientInfo, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::data::DataRow;
use pgwire::messages::PgWireBackendMessage;
use pgwire::api::results::{
    DataRowEncoder, FieldInfo, FieldFormat,
    QueryResponse, Response, Tag,
};
use pgwire::api::stmt::QueryParser;
use postgres_types::{to_sql_checked, IsNull, ToSql};
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

struct ParsedMessages {
    columns: Option<Arc<Vec<FieldInfo>>>,
    data_rows: Vec<PgWireResult<DataRow>>,
    rows_count: usize,
}

/// Holds the backend Postgres connection for a client socket, shared between
/// `StartupHandler` (sets it after auth) and `ProxyQueryHandler` (uses it for queries).
///
/// `Arc<Session>` lives for the socket lifetime. When the last `Arc` is dropped
/// (after `process_socket` returns), `Drop` returns the connection to the pool.
/// `RecyclingMethod::Clean` runs `DISCARD ALL` at the next checkout, preventing session state leaks.
pub struct Session {
    pub(crate) inner: Arc<Mutex<Option<deadpool_postgres::Object>>>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(mut mutex_guard) = self.inner.try_lock() {
            let _conn = mutex_guard.take();
        } else {
            tracing::error!(
                "Session::drop: try_lock failed (poisoned mutex) — backend connection not returned to pool"
            );
        }
    }
}

/// Query handler that shares a single backend connection per socket.
pub struct ProxyQueryHandler {
    manager: Arc<ConnectionManager>,
    session: Arc<Session>,
    query_parser: Arc<PostgresQueryParser>,
}

impl ProxyQueryHandler {
    pub fn new(manager: Arc<ConnectionManager>, session: Arc<Session>) -> Self {
        let query_parser = Arc::new(PostgresQueryParser::new(session.clone(), manager.clone()));
        Self { manager, session, query_parser }
    }

    fn get_user_id<C: ClientInfo>(&self, client: &C) -> PgWireResult<String> {
        client
            .metadata()
            .get(METADATA_USER_ID)
            .cloned()
            .ok_or_else(|| {
                PgWireError::ApiError(Box::new(ProxyError::InvalidStartup("no user_id".into())))
            })
    }

    /// Acquire the session connection, run `sql`, restore the connection, return the raw messages.
    async fn run_query(
        &self,
        sql: &str,
        fallback_user_id: Option<&str>,
    ) -> PgWireResult<Result<Vec<tokio_postgres::SimpleQueryMessage>, tokio_postgres::Error>> {
        let backend = { self.session.inner.lock().await.take() };

        let backend = match (backend, fallback_user_id) {
            (Some(c), _) => c,
            (None, Some(uid)) => {
                tracing::warn!("session has no backend connection, checking out per-query");
                self.manager
                    .check_out(uid)
                    .await
                    .map_err(|e| PgWireError::ApiError(Box::new(e)))?
            }
            (None, None) => {
                return Err(PgWireError::UserError(Box::new(ErrorInfo::new(
                    "FATAL".into(),
                    "50000".into(),
                    "no backend connection in session".into(),
                ))));
            }
        };

        // Capture result first, restore backend before propagating.
        // This prevents connection leaks when simple_query fails.
        let result = backend.simple_query(sql).await;
        {
            let mut guard = self.session.inner.lock().await;
            if guard.is_none() {
                *guard = Some(backend);
            }
        }

        Ok(result)
    }

    /// Parse raw `SimpleQueryMessage`s into columns + encoded rows.
    fn parse_messages(
        messages: Vec<tokio_postgres::SimpleQueryMessage>,
    ) -> ParsedMessages {
        let mut columns: Option<Arc<Vec<FieldInfo>>> = None;
        let mut data_rows: Vec<PgWireResult<DataRow>> = Vec::new();
        let mut rows_count = 0usize;

        for msg in messages {
            match msg {
                tokio_postgres::SimpleQueryMessage::RowDescription(cols) => {
                    let fields: Vec<FieldInfo> = cols
                        .iter()
                        .map(|col| {
                            FieldInfo::new(
                                col.name().to_string(),
                                None,
                                None,
                                Type::UNKNOWN,
                                pgwire::api::results::FieldFormat::Text,
                            )
                        })
                        .collect();
                    columns = Some(Arc::new(fields));
                }
                tokio_postgres::SimpleQueryMessage::Row(row) => {
                    let cols = match &columns {
                        Some(c) => c.clone(),
                        None => continue,
                    };
                    let mut encoder = DataRowEncoder::new(cols.clone());
                    for col in row.columns() {
                        let val: Option<&str> = row.get(col.name());
                        if let Some(s) = val {
                            let _ = encoder.encode_field(&s);
                        } else {
                            let _ = encoder.encode_field::<Option<String>>(&None);
                        }
                    }
                    data_rows.push(Ok(encoder.take_row()));
                    rows_count += 1;
                }
                _ => {}
            }
        }

        ParsedMessages { columns, data_rows, rows_count }
    }

    fn exec_query(messages: Vec<tokio_postgres::SimpleQueryMessage>) -> Vec<Response> {
        let ParsedMessages { columns, data_rows, rows_count } = Self::parse_messages(messages);
        if let Some(cols) = columns {
            let row_stream: Pin<Box<dyn Stream<Item = PgWireResult<DataRow>> + Send>> =
                Box::pin(stream::iter(data_rows));
            let mut qr = QueryResponse::new(cols, row_stream);
            qr.set_command_tag(&format!("SELECT {}", rows_count));
            vec![Response::Query(qr)]
        } else {
            vec![Response::EmptyQuery]
        }
    }

    fn exec_command_tag(messages: Vec<tokio_postgres::SimpleQueryMessage>) -> Tag {
        let mut rows_affected = 0u64;
        for msg in messages {
            if let tokio_postgres::SimpleQueryMessage::CommandComplete(count) = msg {
                rows_affected = count;
            }
        }
        Tag::new("OK").with_rows(rows_affected as usize)
    }
}

impl Clone for ProxyQueryHandler {
    fn clone(&self) -> Self {
        Self::new(self.manager.clone(), self.session.clone())
    }
}

#[async_trait]
impl pgwire::api::query::SimpleQueryHandler for ProxyQueryHandler {
    async fn do_query<C>(&self, client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + Send + Sync + Unpin,
    {
        let user_id = self.get_user_id(client)?;
        tracing::debug!(user_id = %user_id, query = %query, "do_query");

        let messages = self.run_query(query, Some(&user_id)).await?;

        match messages {
            Ok(msgs) => {
                let upper = query.trim().to_uppercase();
                let mut responses = if is_select_query(&upper) {
                    Self::exec_query(msgs)
                } else {
                    vec![Response::Execution(Self::exec_command_tag(msgs))]
                };

                if upper == "BEGIN" || upper.starts_with("BEGIN ") {
                    responses.push(Response::TransactionStart(Tag::new("BEGIN")));
                } else if upper == "COMMIT" {
                    responses.push(Response::TransactionEnd(Tag::new("COMMIT")));
                } else if upper == "ROLLBACK" || upper.starts_with("ABORT") {
                    responses.push(Response::TransactionEnd(Tag::new("ROLLBACK")));
                }

                Ok(responses)
            }
            Err(e) => {
                tracing::warn!(error = %e, "query error");
                Ok(vec![Response::Error(Box::new(ErrorInfo::new(
                    "ERROR".into(),
                    "42000".into(),
                    e.to_string(),
                )))])
            }
        }
    }
}

/// Wraps a raw parameter value with its Postgres type and wire format.
/// Implements `ToSql` so it can be passed to tokio_postgres `query_raw`.
/// tokio-postgres prepared statements return rows in binary format by default.
#[derive(Debug)]
pub struct RawParam {
    // NOTE: the type field is not used in to_sql (only format + bytes are needed).
    // Kept for documentation and potential future use (e.g., validation).
    #[allow(dead_code)]
    type_: Type,
    format: FieldFormat,
    bytes: Option<Bytes>,
}

impl RawParam {
    pub fn new(type_: Type, format: FieldFormat, bytes: Option<Bytes>) -> Self {
        Self { type_, format, bytes }
    }
}

impl ToSql for RawParam {
    fn to_sql(
        &self,
        ty: &Type,
        w: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match &self.bytes {
            None => Ok(IsNull::Yes),
            Some(bytes) => {
                if self.format == FieldFormat::Binary {
                    w.extend_from_slice(bytes);
                    Ok(IsNull::No)
                } else {
                    // Text format: decode the text bytes into a typed Rust value
                    // and re-encode via the Type's ToSql impl.
                    decode_text_param(bytes.as_ref(), &self.type_, ty, w)
                }
            }
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    to_sql_checked!();
}

/// Decode a text-format parameter value into the appropriate typed value,
/// then write it via the target Type's ToSql implementation.
fn decode_text_param(
    text_bytes: &[u8],
    _source_type: &Type,
    target_type: &Type,
    out: &mut BytesMut,
) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
    match target_type.oid() {
        16 => {
            // BOOL
            let s = std::str::from_utf8(text_bytes)?;
            let b = matches!(s.trim(), "t" | "true" | "1" | "yes" | "on");
            <bool as ToSql>::to_sql(&b, target_type, out)?;
        }
        21 => {
            // INT2
            let s = std::str::from_utf8(text_bytes)?;
            let v: i16 = s.trim().parse()?;
            <i16 as ToSql>::to_sql(&v, target_type, out)?;
        }
        23 => {
            // INT4
            let s = std::str::from_utf8(text_bytes)?;
            let v: i32 = s.trim().parse()?;
            <i32 as ToSql>::to_sql(&v, target_type, out)?;
        }
        20 | 1016 => {
            // INT8 or INT8_ARRAY element
            let s = std::str::from_utf8(text_bytes)?;
            let v: i64 = s.trim().parse()?;
            <i64 as ToSql>::to_sql(&v, target_type, out)?;
        }
        700 => {
            // FLOAT4
            let s = std::str::from_utf8(text_bytes)?;
            let v: f32 = s.trim().parse()?;
            <f32 as ToSql>::to_sql(&v, target_type, out)?;
        }
        701 => {
            // FLOAT8
            let s = std::str::from_utf8(text_bytes)?;
            let v: f64 = s.trim().parse()?;
            <f64 as ToSql>::to_sql(&v, target_type, out)?;
        }
        25 | 1043 | 19 | 142 | 705 | 1042 => {
            // TEXT, VARCHAR, NAME, XML, unknown, CHAR
            let s = std::str::from_utf8(text_bytes)?.to_owned();
            <String as ToSql>::to_sql(&s, target_type, out)?;
        }
        2950 => {
            // UUID
            let s = std::str::from_utf8(text_bytes)?;
            let u = uuid::Uuid::parse_str(s.trim())?;
            <uuid::Uuid as ToSql>::to_sql(&u, target_type, out)?;
        }
        114 | 3802 => {
            // JSON, JSONPATH
            let s = std::str::from_utf8(text_bytes)?.to_owned();
            let v: serde_json::Value = serde_json::from_str(&s)?;
            <serde_json::Value as ToSql>::to_sql(&v, target_type, out)?;
        }
        1114 | 1184 | 1082 | 1083 | 1266 => {
            // TIMESTAMP, TIMESTAMPTZ, DATE, TIME, TIMETZ
            let s = std::str::from_utf8(text_bytes)?;
            let v: chrono::NaiveDateTime = chrono::NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S%.f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S"))
                .map_err(|e| format!("invalid datetime: {}", e))?;
            <chrono::NaiveDateTime as ToSql>::to_sql(&v, target_type, out)?;
        }
        1700 => {
            // NUMERIC
            let s = std::str::from_utf8(text_bytes)?;
            let v: rust_decimal::Decimal = s.trim().parse()
                .map_err(|e| format!("invalid decimal: {}", e))?;
            <rust_decimal::Decimal as ToSql>::to_sql(&v, target_type, out)?;
        }
        _ => {
            // Fallback: try to pass as text
            let s = std::str::from_utf8(text_bytes)?.to_owned();
            <String as ToSql>::to_sql(&s, target_type, out)?;
        }
    }
    Ok(IsNull::No)
}

/// Encode a single column value from a tokio_postgres Row into the encoder.
/// tokio-postgres prepared statements return rows in binary format by default.
/// When the client requests Text format, we decode the binary bytes ourselves and
/// re-encode as pgwire text; when it requests Binary, we pass raw bytes through.
fn encode_column_value(
    row: &tokio_postgres::Row,
    idx: usize,
    oid: u32,
    encoder: &mut DataRowEncoder,
) -> PgWireResult<()> {
    macro_rules! try_get {
        ($ty:ty) => {
            row.try_get::<_, $ty>(idx).map_err(|e| PgWireError::ApiError(Box::new(e)))
        };
    }

    macro_rules! encode {
        ($v:expr) => {
            encoder.encode_field($v)
        };
    }

    match oid {
        16 => encode!(&try_get!(bool)?),
        21 => encode!(&try_get!(i16)?),
        23 => encode!(&try_get!(i32)?),
        20 => encode!(&try_get!(i64)?),
        700 => encode!(&try_get!(f32)?),
        701 => encode!(&try_get!(f64)?),
        25 | 1043 | 19 | 142 | 705 | 1042 => encode!(&try_get!(String)?),
        2950 => encode!(&try_get!(String)?),
        17 => encode!(&try_get!(Vec<u8>)?),
        114 | 3802 => encode!(&try_get!(serde_json::Value)?),
        1114 | 1184 => encode!(&try_get!(chrono::NaiveDateTime)?),
        1082 => encode!(&try_get!(chrono::NaiveDate)?),
        1083 => encode!(&try_get!(chrono::NaiveTime)?),
        1700 => encode!(&try_get!(rust_decimal::Decimal)?),
        _ => Err(PgWireError::UserError(Box::new(ErrorInfo::new(
            "0A000".into(),
            oid.to_string(),
            format!("unsupported column type OID {}", oid),
        )))),
    }
}

fn parse_dml_verb(sql: &str) -> &'static str {
    let upper = sql.trim_start().to_uppercase();
    let rest = if upper.starts_with("WITH") {
        // Skip CTEs: find matching ')' then next keyword
        skip_cte(&upper)
    } else {
        &upper
    };
    if rest.starts_with("INSERT") {
        "INSERT"
    } else if rest.starts_with("UPDATE") {
        "UPDATE"
    } else if rest.starts_with("DELETE") {
        "DELETE"
    } else if rest.starts_with("MERGE") {
        "MERGE"
    } else if rest.starts_with("TRUNCATE") {
        "TRUNCATE"
    } else if rest.starts_with("VACUUM") {
        "VACUUM"
    } else {
        "OK"
    }
}

fn skip_cte(upper: &str) -> &str {
    let mut depth = 0usize;
    let mut paren_end = 0usize;
    for (i, c) in upper.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    paren_end = i + c.len_utf8();
                    break;
                }
            }
            _ => {}
        }
    }
    if paren_end > 0 {
        upper[paren_end..].trim_start()
    } else {
        upper
    }
}

/// Wrapper around tokio_postgres::Statement that also stores the original SQL string.
/// This lets us retrieve the SQL for DML verb parsing in do_query.
#[derive(Clone)]
pub struct StatementWithSql {
    pub(crate) inner: tokio_postgres::Statement,
    pub(crate) sql: String,
}

/// QueryParser that uses real Postgres prepared statements.
#[derive(Clone)]
pub struct PostgresQueryParser {
    session: Arc<Session>,
    manager: Arc<ConnectionManager>,
}

impl PostgresQueryParser {
    pub fn new(session: Arc<Session>, manager: Arc<ConnectionManager>) -> Self {
        Self { session, manager }
    }
}

#[async_trait]
impl QueryParser for PostgresQueryParser {
    type Statement = StatementWithSql;

    async fn parse_sql<C>(
        &self,
        client_info: &C,
        query: &str,
        _param_types: &[Option<Type>],
    ) -> PgWireResult<Self::Statement>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        let user_id = client_info
            .metadata()
            .get(METADATA_USER_ID)
            .cloned()
            .ok_or_else(|| {
                PgWireError::ApiError(Box::new(ProxyError::InvalidStartup("no user_id".into())))
            })?;

        let backend = { self.session.inner.lock().await.take() };

        let backend = match backend {
            Some(c) => c,
            None => {
                self.manager
                    .check_out(&user_id)
                    .await
                    .map_err(|e| PgWireError::ApiError(Box::new(e)))?
            }
        };

        // Build type list: map None → Type::UNKNOWN, preserving length
        let types: Vec<postgres_types::Type> = _param_types
            .iter()
            .map(|t| {
                t.clone()
                    .map(|ty| {
                        postgres_types::Type::from_oid(ty.oid())
                            .unwrap_or(postgres_types::Type::UNKNOWN)
                    })
                    .unwrap_or(postgres_types::Type::UNKNOWN)
            })
            .collect();

        // Capture result first, restore backend before propagating.
        // This prevents connection leaks when prepare_typed fails.
        let result = backend.prepare_typed(query, &types).await;
        {
            let mut guard = self.session.inner.lock().await;
            if guard.is_none() {
                *guard = Some(backend);
            }
        }

        let stmt = result.map_err(|e| PgWireError::ApiError(Box::new(e)))?;
        let sql_owned = query.to_owned();

        Ok(StatementWithSql { inner: stmt, sql: sql_owned })
    }

    fn get_parameter_types(&self, stmt: &Self::Statement) -> PgWireResult<Vec<Type>> {
        let params: Vec<Type> = stmt
            .inner
            .params()
            .iter()
            .map(|ty| {
                Type::from_oid(ty.oid())
                    .unwrap_or(Type::UNKNOWN)
            })
            .collect();
        Ok(params)
    }

    fn get_result_schema(
        &self,
        stmt: &Self::Statement,
        column_format: Option<&pgwire::api::portal::Format>,
    ) -> PgWireResult<Vec<FieldInfo>> {
        let cols = stmt.inner.columns();
        let mut fields = Vec::with_capacity(cols.len());
        for (i, col) in cols.iter().enumerate() {
            let fmt = column_format
                .map(|f| f.format_for(i))
                .unwrap_or(FieldFormat::Text);
            fields.push(FieldInfo::new(
                col.name().to_string(),
                None,
                None,
                Type::from_oid(col.type_().oid())
                    .unwrap_or(Type::UNKNOWN),
                fmt,
            ));
        }
        Ok(fields)
    }
}

/// Intermediate result type: owned data collected inside the async block.
/// Used to avoid lifetime issues from capturing `backend` in the return type.
enum QueryExecResult {
    Dml {
        rows_affected: usize,
        verb: String,
    },
    Select {
        fields: Vec<FieldInfo>,
        data_rows: Vec<DataRow>,
        row_count: usize,
    },
}

#[async_trait]
impl ExtendedQueryHandler for ProxyQueryHandler {
    type Statement = StatementWithSql;
    type QueryParser = PostgresQueryParser;

    fn query_parser(&self) -> Arc<Self::QueryParser> {
        self.query_parser.clone()
    }

    async fn do_query<C>(
        &self,
        client: &mut C,
        portal: &Portal<Self::Statement>,
        _max_rows: usize,
    ) -> PgWireResult<Response>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        let _user_id = self.get_user_id(client)?;
        let sws = &portal.statement.statement;
        let stmt = &sws.inner;
        let sql = &sws.sql;

        let is_dml = parse_dml_verb(sql) != "OK";

        let param_types = stmt.params();
        let param_format = portal.parameter_format.clone();
        let result_format = portal.result_column_format.clone();

        let raw_params: Vec<RawParam> = portal
            .parameters
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let ty = param_types
                    .get(i)
                    .cloned()
                    .unwrap_or(postgres_types::Type::UNKNOWN);
                let fmt = param_format.format_for(i);
                RawParam::new(
                    Type::from_oid(ty.oid()).unwrap_or(Type::UNKNOWN),
                    fmt,
                    p.clone(),
                )
            })
            .collect();

        // Clone to move into async blocks below
        let inner_stmt = sws.inner.clone();
        let sql_owned = sws.sql.clone();

        // Acquire backend from session (inlined from with_backend_async)
        let backend = { self.session.inner.lock().await.take() };

        let backend = match backend {
            Some(c) => c,
            None => {
                tracing::warn!("session has no backend, checking out per-query");
                self.manager
                    .check_out(&_user_id)
                    .await
                    .map_err(|e| PgWireError::ApiError(Box::new(e)))?
            }
        };

        // Execute query while holding backend. IMPORTANT: `execute_raw`/`query_raw`
        // return a value (not a future) — we can capture the result, restore the backend,
        // then propagate. This avoids the `?` short-circuiting before restore.
        //
        // This is the key fix for the connection-leak-on-error bug: all error paths
        // now restore `backend` to the session before returning.
        let query_data_result: QueryExecResult = if inner_stmt.columns().is_empty() || is_dml {
            // DML: capture result first, restore, then propagate
            let raw_result = backend
                .execute_raw(&inner_stmt, raw_params.iter())
                .await
                .map_err(|e| PgWireError::ApiError(Box::new(e)));
            // Restore backend before propagating error
            {
                let mut guard = self.session.inner.lock().await;
                if guard.is_none() {
                    *guard = Some(backend);
                }
            }
            // Now propagate if error, otherwise build Dml result
            match raw_result {
                Ok(n) => {
                    let verb = parse_dml_verb(&sql_owned);
                    QueryExecResult::Dml {
                        rows_affected: n as usize,
                        verb: verb.to_string(),
                    }
                }
                Err(e) => return Err(e),
            }
        } else {
            // SELECT: collect rows into owned Vec<DataRow>
            let raw_stream_result = backend
                .query_raw(&inner_stmt, raw_params.iter())
                .await
                .map_err(|e| PgWireError::ApiError(Box::new(e)));
            // Restore backend before propagating
            {
                let mut guard = self.session.inner.lock().await;
                if guard.is_none() {
                    *guard = Some(backend);
                }
            }
            let row_stream = match raw_stream_result {
                Ok(rs) => rs,
                Err(e) => return Err(e),
            };

            let rows: Vec<tokio_postgres::Row> = match row_stream.try_collect().await {
                Ok(r) => r,
                Err(e) => return Err(PgWireError::ApiError(Box::new(e))),
            };

            let columns = inner_stmt.columns();
            let result_formats: Vec<FieldFormat> = (0..columns.len())
                .map(|i| result_format.format_for(i))
                .collect();

            let fields: Vec<FieldInfo> = columns
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    FieldInfo::new(
                        col.name().to_string(),
                        None,
                        None,
                        Type::from_oid(col.type_().oid())
                            .unwrap_or(Type::UNKNOWN),
                        *result_formats.get(i).unwrap_or(&FieldFormat::Text),
                    )
                })
                .collect();

            let mut data_rows = Vec::with_capacity(rows.len());
            for row in &rows {
                let mut encoder = DataRowEncoder::new(Arc::new(fields.clone()));

                for (col_idx, _col) in columns.iter().enumerate() {
                    let oid = columns[col_idx].type_().oid();
                    encode_column_value(row, col_idx, oid, &mut encoder)?;
                }
                data_rows.push(encoder.take_row());
            }

            QueryExecResult::Select {
                fields,
                data_rows,
                row_count: rows.len(),
            }
        };

        // Build Response from owned query_data_result
        let result = match query_data_result {
            QueryExecResult::Dml { rows_affected, verb } => {
                Response::Execution(Tag::new(&verb).with_rows(rows_affected))
            }
            QueryExecResult::Select { fields, data_rows, row_count } => {
                let cols = Arc::new(fields);
                let row_stream: Pin<Box<dyn Stream<Item = PgWireResult<DataRow>> + Send>> =
                    Box::pin(stream::iter(data_rows.into_iter().map(Ok)));
                let mut qr = QueryResponse::new(cols, row_stream);
                qr.set_command_tag(&format!("SELECT {}", row_count));
                Response::Query(qr)
            }
        };

        Ok(result)
    }
}

/// Substitute PostgreSQL `$1`, `$2`, ... placeholders with parameter values.
/// Parameters are expected in text format (Bytes encoding a UTF-8 string).
#[allow(dead_code)]
fn substitute_params(sql: &str, params: &[Option<Bytes>]) -> String {
    if params.is_empty() {
        return sql.to_string();
    }
    let mut result = String::with_capacity(sql.len() + params.len() * 16);
    let bytes = sql.as_bytes();
    let mut param_idx = 0usize;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            let start = i;
            i += 1;
            let mut num = 0usize;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                num = num * 10 + (bytes[i] - b'0') as usize;
                i += 1;
            }
            if i > start + 1 && (i >= bytes.len() || !bytes[i].is_ascii_digit()) {
                param_idx += 1;
                if num == param_idx {
                    if let Some(Some(p)) = params.get(param_idx - 1) {
                        if let Ok(s) = std::str::from_utf8(p) {
                            result.push('\'');
                            result.push_str(&escape_pg_string(s));
                            result.push('\'');
                            continue;
                        }
                    }
                    result.push_str(&sql[start..i]);
                    continue;
                } else {
                    i = start + 1;
                    result.push('$');
                    continue;
                }
            }
            i = start + 1;
            result.push('$');
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Escape a string value for use in a PostgreSQL literal.
pub(crate) fn escape_pg_string(s: &str) -> String {
    let mut r = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\'' => r.push_str("''"),
            '\\' => r.push_str("\\\\"),
            '\n' => r.push_str("\\n"),
            '\r' => r.push_str("\\r"),
            '\t' => r.push_str("\\t"),
            _ => r.push(c),
        }
    }
    r
}

fn is_select_query(q: &str) -> bool {
    q.starts_with("SELECT")
        || q.starts_with("WITH")
        || q.starts_with("TABLE")
        || q.starts_with("VALUES")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── escape_pg_string ──────────────────────────────────────────────────

    #[test]
    fn test_escape_single_quote() {
        assert_eq!(escape_pg_string("it's fine"), "it''s fine");
    }

    #[test]
    fn test_escape_backslash() {
        assert_eq!(escape_pg_string("C:\\path"), "C:\\\\path");
    }

    #[test]
    fn test_escape_newline() {
        assert_eq!(escape_pg_string("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_escape_cr_tab() {
        assert_eq!(escape_pg_string("a\rb\tc"), "a\\rb\\tc");
    }

    #[test]
    fn test_escape_empty() {
        assert_eq!(escape_pg_string(""), "");
    }

    #[test]
    fn test_escape_no_special_chars() {
        assert_eq!(escape_pg_string("hello world"), "hello world");
    }

    // ── substitute_params ─────────────────────────────────────────────────

    fn p(s: &str) -> Option<Bytes> {
        Some(Bytes::from(s.to_string()))
    }

    #[test]
    fn test_substitute_basic() {
        let sql = "SELECT * FROM t WHERE id = $1";
        let result = substitute_params(sql, &[p("abc")]);
        assert_eq!(result, "SELECT * FROM t WHERE id = 'abc'");
    }

    #[test]
    fn test_substitute_quote_injection() {
        let sql = "SELECT * FROM users WHERE name = $1";
        let result = substitute_params(sql, &[p("O'Brien")]);
        assert_eq!(result, "SELECT * FROM users WHERE name = 'O''Brien'");
    }

    #[test]
    fn test_substitute_backslash() {
        let sql = "SELECT $1";
        let result = substitute_params(sql, &[p("a\\b")]);
        assert_eq!(result, "SELECT 'a\\\\b'");
    }

    #[test]
    fn test_substitute_multiple_params() {
        let sql = "INSERT INTO t (a, b) VALUES ($1, $2)";
        let result = substitute_params(sql, &[p("foo"), p("bar")]);
        assert_eq!(result, "INSERT INTO t (a, b) VALUES ('foo', 'bar')");
    }

    #[test]
    fn test_substitute_null_param_leaves_placeholder() {
        let sql = "SELECT $1";
        let result = substitute_params(sql, &[None]);
        assert_eq!(result, "SELECT $1");
    }

    #[test]
    fn test_substitute_no_params() {
        let sql = "SELECT 1";
        let result = substitute_params(sql, &[]);
        assert_eq!(result, "SELECT 1");
    }

    #[test]
    fn test_substitute_non_utf8_leaves_placeholder() {
        let sql = "SELECT $1";
        let bad_bytes = Some(Bytes::from(vec![0xFF, 0xFE]));
        let result = substitute_params(sql, &[bad_bytes]);
        assert_eq!(result, "SELECT $1");
    }

    #[test]
    fn test_substitute_out_of_order_leaves_unsubstituted() {
        let sql = "SELECT $2, $1";
        let result = substitute_params(sql, &[p("first"), p("second")]);
        assert_eq!(result, "SELECT $2, $1");
    }

    #[test]
    fn test_substitute_repeated_placeholder_second_unsubstituted() {
        let sql = "SELECT $1, $1";
        let result = substitute_params(sql, &[p("val")]);
        assert_eq!(result, "SELECT 'val', $1");
    }

    #[test]
    fn test_substitute_type_cast_delimiter() {
        let sql = "SELECT $1::text";
        let result = substitute_params(sql, &[p("hello")]);
        assert_eq!(result, "SELECT 'hello'::text");
    }

    // ── is_select_query ───────────────────────────────────────────────────

    #[test]
    fn test_is_select_query_variants() {
        assert!(is_select_query("SELECT 1"));
        assert!(is_select_query("WITH cte AS (SELECT 1) SELECT * FROM cte"));
        assert!(is_select_query("TABLE users"));
        assert!(is_select_query("VALUES (1, 2)"));
        assert!(!is_select_query("INSERT INTO users VALUES (1)"));
        assert!(!is_select_query("UPDATE users SET name = 'x'"));
        assert!(!is_select_query("DELETE FROM users"));
    }

    // ── parse_dml_verb ────────────────────────────────────────────────────

    #[test]
    fn test_parse_dml_verb() {
        assert_eq!(parse_dml_verb("INSERT INTO t VALUES (1)"), "INSERT");
        assert_eq!(parse_dml_verb("UPDATE t SET x = 1"), "UPDATE");
        assert_eq!(parse_dml_verb("DELETE FROM t WHERE x = 1"), "DELETE");
        assert_eq!(parse_dml_verb("MERGE INTO t USING s ON t.id = s.id"), "MERGE");
        assert_eq!(parse_dml_verb("TRUNCATE TABLE t"), "TRUNCATE");
        assert_eq!(parse_dml_verb("VACUUM"), "VACUUM");
        assert_eq!(parse_dml_verb("SELECT 1"), "OK");
    }

    #[test]
    fn test_parse_dml_verb_with_cte() {
        assert_eq!(
            parse_dml_verb("WITH t AS (SELECT 1) INSERT INTO users VALUES (1)"),
            "INSERT"
        );
        assert_eq!(
            parse_dml_verb("WITH t AS (SELECT 1) UPDATE users SET x = 1"),
            "UPDATE"
        );
        assert_eq!(
            parse_dml_verb("WITH t AS (SELECT 1) DELETE FROM users WHERE x = 1"),
            "DELETE"
        );
    }

    // ── decode_text_param ─────────────────────────────────────────────────

    use bytes::BytesMut;

    fn round_trip_text_param(text: &str, oid: u32) -> Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>> {
        let text_bytes = text.as_bytes();
        let ty = Type::from_oid(oid).unwrap_or(Type::UNKNOWN);
        let target = Type::from_oid(oid).unwrap_or(Type::UNKNOWN);
        let mut out = BytesMut::new();
        decode_text_param(text_bytes, &ty, &target, &mut out)?;
        Ok(out.freeze())
    }

    #[test]
    fn test_decode_text_bool() {
        for (input, expected) in [("t", true), ("true", true), ("1", true), ("yes", true), ("on", true),
                                   ("f", false), ("false", false), ("0", false), ("no", false), ("off", false)] {
            let result = round_trip_text_param(input, 16).unwrap();
            let ty = Type::from_oid(16).unwrap();
            let restored: bool = <bool as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
            assert_eq!(restored, expected, "input={}", input);
        }
    }

    #[test]
    fn test_decode_text_int2() {
        for (input, expected) in [("0", 0i16), ("1", 1i16), ("-1", -1i16), ("32767", 32767i16)] {
            let result = round_trip_text_param(input, 21).unwrap();
            let ty = Type::from_oid(21).unwrap();
            let restored: i16 = <i16 as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
            assert_eq!(restored, expected, "input={}", input);
        }
    }

    #[test]
    fn test_decode_text_int4() {
        for (input, expected) in [("0", 0i32), ("42", 42i32), ("-100", -100i32)] {
            let result = round_trip_text_param(input, 23).unwrap();
            let ty = Type::from_oid(23).unwrap();
            let restored: i32 = <i32 as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
            assert_eq!(restored, expected, "input={}", input);
        }
    }

    #[test]
    fn test_decode_text_int8() {
        for (input, expected) in [("0", 0i64), ("9223372036854775807", 9223372036854775807i64)] {
            let result = round_trip_text_param(input, 20).unwrap();
            let ty = Type::from_oid(20).unwrap();
            let restored: i64 = <i64 as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
            assert_eq!(restored, expected, "input={}", input);
        }
    }

    #[test]
    fn test_decode_text_float4() {
        let result = round_trip_text_param("3.14", 700).unwrap();
        let ty = Type::from_oid(700).unwrap();
        let restored: f32 = <f32 as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert!((restored - std::f32::consts::PI).abs() < 0.001);
    }

    #[test]
    fn test_decode_text_float8() {
        let result = round_trip_text_param("3.14159265358979", 701).unwrap();
        let ty = Type::from_oid(701).unwrap();
        let restored: f64 = <f64 as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert!((restored - std::f64::consts::PI).abs() < 1e-10);
    }

    #[test]
    fn test_decode_text_text() {
        let result = round_trip_text_param("hello world", 25).unwrap();
        let ty = Type::from_oid(25).unwrap();
        let restored: String = <String as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored, "hello world");
    }

    #[test]
    fn test_decode_text_text_with_special_chars() {
        for input in ["O'Brien", "a\\b", "multi\nline", "trailing\t"] {
            let result = round_trip_text_param(input, 25).unwrap();
            let ty = Type::from_oid(25).unwrap();
            let restored: String = <String as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
            assert_eq!(restored, input, "input={:?}", input);
        }
    }

    #[test]
    fn test_decode_text_uuid() {
        let input = "550e8400-e29b-41d4-a716-446655440000";
        let result = round_trip_text_param(input, 2950).unwrap();
        let ty = Type::from_oid(2950).unwrap();
        let restored: uuid::Uuid = <uuid::Uuid as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored.to_string(), input);
    }

    #[test]
    fn test_decode_text_uuid_invalid() {
        let result = round_trip_text_param("not-a-uuid", 2950);
        assert!(result.is_err(), "invalid UUID should return error");
    }

    #[test]
    fn test_decode_text_numeric() {
        let input = "123.45";
        let result = round_trip_text_param(input, 1700).unwrap();
        let ty = Type::from_oid(1700).unwrap();
        let restored: rust_decimal::Decimal = <rust_decimal::Decimal as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored.to_string(), "123.45");
    }

    #[test]
    fn test_decode_text_numeric_invalid() {
        let result = round_trip_text_param("not-a-number", 1700);
        assert!(result.is_err(), "invalid numeric should return error");
    }

    #[test]
    fn test_decode_text_json() {
        let input = r#"{"key":"value","num":42}"#;
        let result = round_trip_text_param(input, 114).unwrap();
        let ty = Type::from_oid(114).unwrap();
        let restored: serde_json::Value = <serde_json::Value as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored["key"], "value");
        assert_eq!(restored["num"], 42);
    }

    #[test]
    fn test_decode_text_datetime() {
        let input = "2024-01-15 10:30:00";
        let result = round_trip_text_param(input, 1114).unwrap();
        let ty = Type::from_oid(1114).unwrap();
        let restored: chrono::NaiveDateTime = <chrono::NaiveDateTime as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored.date().to_string(), "2024-01-15");
    }

    #[test]
    fn test_decode_text_datetime_with_microseconds() {
        let input = "2024-01-15 10:30:00.123456";
        let result = round_trip_text_param(input, 1114).unwrap();
        let ty = Type::from_oid(1114).unwrap();
        let restored: chrono::NaiveDateTime = <chrono::NaiveDateTime as postgres_types::FromSql>::from_sql(&ty, &result).unwrap();
        assert_eq!(restored.date().to_string(), "2024-01-15");
    }

    #[test]
    fn test_decode_text_datetime_invalid() {
        let result = round_trip_text_param("not-a-datetime", 1114);
        assert!(result.is_err(), "invalid datetime should return error");
    }

    #[test]
    fn test_decode_text_unknown_oid_falls_back_to_string() {
        // OID 12345 is not in our known set — falls back to text encoding
        let result = round_trip_text_param("fallback value", 12345);
        assert!(result.is_ok(), "unknown OID should fall back to string");
    }
}
