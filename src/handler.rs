use crate::auth::METADATA_USER_ID;
use crate::error::ProxyError;
use crate::pool::ConnectionManager;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream, Sink, Stream};
use pgwire::api::portal::Portal;
use pgwire::api::query::ExtendedQueryHandler;
use pgwire::api::results::{DataRowEncoder, FieldInfo, QueryResponse, Response, Tag};
use pgwire::api::stmt::QueryParser;
use pgwire::api::{ClientInfo, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::data::DataRow;
use pgwire::messages::PgWireBackendMessage;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

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

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(mut mutex_guard) = self.inner.try_lock() {
            let _conn = mutex_guard.take();
        }
    }
}

/// Query handler that shares a single backend connection per socket.
pub struct ProxyQueryHandler {
    manager: Arc<ConnectionManager>,
    session: Arc<Session>,
}

impl ProxyQueryHandler {
    pub fn new(manager: Arc<ConnectionManager>, session: Arc<Session>) -> Self {
        Self { manager, session }
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

    fn exec_query(messages: Vec<tokio_postgres::SimpleQueryMessage>) -> Vec<Response> {
        let mut responses = Vec::new();
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
                tokio_postgres::SimpleQueryMessage::CommandComplete(_tag) => {}
                _ => {}
            }
        }

        if let Some(cols) = columns {
            let row_stream: Pin<Box<dyn Stream<Item = PgWireResult<DataRow>> + Send>> =
                Box::pin(stream::iter(data_rows));
            let mut qr = QueryResponse::new(cols, row_stream);
            qr.set_command_tag(&format!("SELECT {}", rows_count));
            responses.push(Response::Query(qr));
        } else if rows_count == 0 {
            responses.push(Response::EmptyQuery);
        }

        responses
    }

    fn exec_query_stream(
        &self,
        messages: Vec<tokio_postgres::SimpleQueryMessage>,
    ) -> QueryResponse {
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

        match columns {
            Some(cols) => {
                let row_stream: Pin<Box<dyn Stream<Item = PgWireResult<DataRow>> + Send>> =
                    Box::pin(stream::iter(data_rows));
                let mut qr = QueryResponse::new(cols, row_stream);
                qr.set_command_tag(&format!("SELECT {}", rows_count));
                qr
            }
            None => {
                let cols = Arc::new(Vec::new());
                let row_stream: Pin<Box<dyn Stream<Item = PgWireResult<DataRow>> + Send>> =
                    Box::pin(stream::iter(Vec::new()));
                QueryResponse::new(cols, row_stream)
            }
        }
    }

    fn exec_command_tag(&self, messages: Vec<tokio_postgres::SimpleQueryMessage>) -> Tag {
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

        let backend = {
            let mut guard = self.session.inner.lock().await;
            guard.take()
        };

        let backend = match backend {
            Some(c) => c,
            None => {
                tracing::warn!("session has no backend connection, checking out per-query");
                self.manager
                    .check_out(&user_id)
                    .await
                    .map_err(|e| PgWireError::ApiError(Box::new(e)))?
            }
        };

        let messages = backend.simple_query(query).await;

        {
            let mut guard = self.session.inner.lock().await;
            if guard.is_none() {
                *guard = Some(backend);
            }
        }

        match messages {
            Ok(msgs) => {
                let upper = query.trim().to_uppercase();
                let mut responses = if is_select_query(&upper) {
                    Self::exec_query(msgs)
                } else {
                    vec![Response::Execution(self.exec_command_tag(msgs))]
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

#[async_trait]
impl ExtendedQueryHandler for ProxyQueryHandler {
    type Statement = String;
    type QueryParser = StringQueryParser;

    fn query_parser(&self) -> Arc<Self::QueryParser> {
        Arc::new(StringQueryParser)
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
        let query = portal.statement.statement.clone();
        let q = substitute_params(&query, &portal.parameters);
        let upper = query.trim().to_uppercase();

        let backend = {
            let mut guard = self.session.inner.lock().await;
            guard.take()
        };

        let backend = match backend {
            Some(c) => c,
            None => {
                return Err(PgWireError::UserError(Box::new(ErrorInfo::new(
                    "FATAL".into(),
                    "50000".into(),
                    "no backend connection in session".into(),
                ))));
            }
        };

        let messages = backend.simple_query(&q).await;

        {
            let mut guard = self.session.inner.lock().await;
            if guard.is_none() {
                *guard = Some(backend);
            }
        }

        match messages {
            Ok(msgs) => {
                if is_select_query(&upper) {
                    Ok(Response::Query(self.exec_query_stream(msgs)))
                } else {
                    Ok(Response::Execution(self.exec_command_tag(msgs)))
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "extended query error");
                Ok(Response::Error(Box::new(ErrorInfo::new(
                    "ERROR".into(),
                    "42000".into(),
                    e.to_string(),
                ))))
            }
        }
    }
}

/// QueryParser that returns the SQL string as-is (no actual parsing).
#[derive(Debug, Clone, Default)]
pub struct StringQueryParser;

#[async_trait]
impl QueryParser for StringQueryParser {
    type Statement = String;

    async fn parse_sql<C>(
        &self,
        _client_info: &C,
        query: &str,
        _param_types: &[Option<Type>],
    ) -> PgWireResult<Self::Statement>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        Ok(query.to_string())
    }

    fn get_parameter_types(&self, _stmt: &Self::Statement) -> PgWireResult<Vec<Type>> {
        Ok(vec![])
    }

    fn get_result_schema(
        &self,
        _stmt: &Self::Statement,
        _column_format: Option<&pgwire::api::portal::Format>,
    ) -> PgWireResult<Vec<FieldInfo>> {
        Ok(vec![])
    }
}

/// Substitute PostgreSQL `$1`, `$2`, ... placeholders with parameter values.
/// Parameters are expected in text format (Bytes encoding a UTF-8 string).
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
fn escape_pg_string(s: &str) -> String {
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
        // $2 before $1 — both left unsubstituted (sequential-only contract)
        let sql = "SELECT $2, $1";
        let result = substitute_params(sql, &[p("first"), p("second")]);
        assert_eq!(result, "SELECT $2, $1");
    }

    #[test]
    fn test_substitute_repeated_placeholder_second_unsubstituted() {
        // $1 twice — only first substitution fires
        let sql = "SELECT $1, $1";
        let result = substitute_params(sql, &[p("val")]);
        assert_eq!(result, "SELECT 'val', $1");
    }

    #[test]
    fn test_substitute_type_cast_delimiter() {
        // $1 followed by :: should be substituted
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
}
