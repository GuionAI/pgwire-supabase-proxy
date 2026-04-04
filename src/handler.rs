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
use std::collections::HashMap;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_ROW_LIMIT: usize = 1000;

/// Per-session state: holds the backend connection for the lifetime of a frontend session.
/// Connections are acquired in on_startup (after JWT auth) and returned to the pool
/// when the session entry is dropped.
pub(crate) struct Session {
    /// The backend connection, checked out from the per-user pool.
    /// Set to None after DISCARD ALL (when session ends).
    conn: Option<deadpool_postgres::Object>,
}

/// Global registry mapping frontend client address → per-session state.
/// Uses a stable key derived from the client pointer address.
pub(crate) struct SessionRegistry {
    sessions: RwLock<HashMap<u64, Session>>,
}

impl SessionRegistry {
    pub(crate) fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Stable key for a ClientInfo object: uses the address of the client.
    fn client_key<C: ClientInfo>(client: &C) -> u64 {
        client as *const C as u64
    }

    /// Register a session with a checked-out backend connection.
    pub(crate) async fn register(&self, key: u64, conn: deadpool_postgres::Object) {
        self.sessions
            .write()
            .await
            .insert(key, Session { conn: Some(conn) });
    }

    /// Unregister a session and run DISCARD ALL on the connection before returning it to the pool.
    #[allow(dead_code)]
    pub(crate) async fn unregister(&self, key: u64) {
        if let Some(session) = self.sessions.write().await.remove(&key) {
            if let Some(conn) = session.conn {
                let _ = conn.simple_query("DISCARD ALL").await;
            }
        }
    }

    /// Take the connection for a session (call at start of do_query).
    /// Acquires a write lock because this mutates the session (takes the conn).
    async fn take(&self, key: u64) -> Option<deadpool_postgres::Object> {
        self.sessions.write().await.get_mut(&key)?.conn.take()
    }

    /// Return the connection to a session (call at end of do_query).
    /// Acquires a write lock because this mutates the session (restores the conn).
    async fn restore(&self, key: u64, conn: deadpool_postgres::Object) {
        if let Some(session) = self.sessions.write().await.get_mut(&key) {
            session.conn = Some(conn);
        }
    }

    /// Unregister all sessions managed by this registry.
    /// Drains all sessions and runs DISCARD ALL on each connection.
    pub(crate) async fn unregister_all(&self) {
        let sessions: Vec<_> = self.sessions.write().await.drain().collect();
        for (_key, session) in sessions {
            if let Some(conn) = session.conn {
                let _ = conn.simple_query("DISCARD ALL").await;
            }
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ProxyQueryHandler {
    manager: Arc<ConnectionManager>,
    registry: Arc<SessionRegistry>,
}

impl ProxyQueryHandler {
    pub fn new(manager: Arc<ConnectionManager>, registry: Arc<SessionRegistry>) -> Self {
        Self { manager, registry }
    }

    /// Unregister a session's backend connection and return it to the pool.
    /// Called when a client disconnects (after process_socket returns).
    #[allow(dead_code)]
    pub async fn unregister(&self, key: u64) {
        self.registry.unregister(key).await;
    }

    /// Unregister all sessions for this handler.
    /// Called after process_socket returns to clean up the connection's session.
    pub async fn unregister_all(&self) {
        self.registry.unregister_all().await;
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

                    if rows_count >= DEFAULT_ROW_LIMIT {
                        break;
                    }
                }
                tokio_postgres::SimpleQueryMessage::CommandComplete(_tag) => {}
                #[allow(unreachable_patterns)]
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

                    if rows_count >= DEFAULT_ROW_LIMIT {
                        break;
                    }
                }
                #[allow(unreachable_patterns)]
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
        Self::new(self.manager.clone(), self.registry.clone())
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

        let key = SessionRegistry::client_key(client);

        // Session binding: take the backend connection registered in on_startup.
        // The same connection is used for all queries in this session, preserving
        // transaction state (BEGIN/COMMIT work correctly).
        let backend = match self.registry.take(key).await {
            Some(conn) => conn,
            None => {
                // Should not happen: session should be registered in on_startup.
                // Fall back to per-query checkout as a safety measure.
                self.manager.check_out(&user_id).await.map_err(|e| {
                    tracing::warn!(error = %e, "session not found, using per-query checkout");
                    PgWireError::ApiError(Box::new(e))
                })?
            }
        };

        let messages = backend.simple_query(query).await;

        // Restore the connection to the session map after use.
        // The connection is NOT returned to the pool here — it stays bound to the
        // session until the frontend socket closes and unregister is called.
        self.registry.restore(key, backend).await;

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
        let user_id = self.get_user_id(client)?;
        let query = portal.statement.statement.clone();
        let key = SessionRegistry::client_key(client);

        let backend = match self.registry.take(key).await {
            Some(conn) => conn,
            None => self.manager.check_out(&user_id).await.map_err(|_| {
                PgWireError::UserError(Box::new(ErrorInfo::new(
                    "FATAL".into(),
                    "50000".into(),
                    "failed to acquire backend connection".into(),
                )))
            })?,
        };

        let q = substitute_params(&query, &portal.parameters);
        let upper = query.trim().to_uppercase();

        let messages = backend.simple_query(&q).await;

        self.registry.restore(key, backend).await;

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
            if i > start + 1
                && (i >= bytes.len()
                    || bytes[i] == b' '
                    || bytes[i] == b','
                    || bytes[i] == b')'
                    || bytes[i] == b';'
                    || bytes[i] == b'\n'
                    || bytes[i] == b'\r'
                    || bytes[i] == b'\t')
            {
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
            } else {
                i = start + 1;
                result.push('$');
                continue;
            }
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
