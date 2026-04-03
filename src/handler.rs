use crate::auth::METADATA_USER_ID;
use crate::error::ProxyError;
use crate::pool::ConnectionManager;
use async_trait::async_trait;
use futures::{stream, Stream};
use std::pin::Pin;
use pgwire::api::results::{DataRowEncoder, FieldInfo, QueryResponse, Response, Tag};
use pgwire::api::{ClientInfo, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::data::DataRow;
use std::sync::Arc;

const DEFAULT_ROW_LIMIT: usize = 1000;

pub struct ProxyQueryHandler {
    manager: Arc<ConnectionManager>,
}

impl ProxyQueryHandler {
    pub fn new(manager: Arc<ConnectionManager>) -> Self {
        Self { manager }
    }

    fn get_user_id<C: ClientInfo>(&self, client: &C) -> PgWireResult<String> {
        client
            .metadata()
            .get(METADATA_USER_ID)
            .cloned()
            .ok_or_else(|| PgWireError::ApiError(Box::new(ProxyError::InvalidStartup("no user_id".into()))))
    }

    fn exec_query(
        messages: Vec<tokio_postgres::SimpleQueryMessage>,
    ) -> Vec<Response> {
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
                tokio_postgres::SimpleQueryMessage::CommandComplete(_tag) => {
                    // Handled separately
                }
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

    fn exec_command(
        messages: Vec<tokio_postgres::SimpleQueryMessage>,
    ) -> Vec<Response> {
        let mut rows_affected = 0u64;

        for msg in messages {
            if let tokio_postgres::SimpleQueryMessage::CommandComplete(count) = msg {
                rows_affected = count;
            }
        }

        vec![Response::Execution(Tag::new("OK").with_rows(rows_affected as usize))]
    }
}

impl Clone for ProxyQueryHandler {
    fn clone(&self) -> Self {
        Self::new(self.manager.clone())
    }
}

#[async_trait]
impl pgwire::api::query::SimpleQueryHandler for ProxyQueryHandler {
    async fn do_query<C>(&self, _client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + Send + Sync + Unpin,
    {
        let user_id = self.get_user_id(_client)?;
        tracing::debug!(user_id = %user_id, query = %query, "do_query");

        let mut backend = self.manager.check_out(&user_id).await.map_err(|e| {
            tracing::warn!(error = %e, "failed to acquire backend connection");
            PgWireError::ApiError(Box::new(e))
        })?;

        let messages = backend.simple_query(query).await;

        let _manager = self.manager.clone();
        tokio::spawn(async move {
            if let Err(e) = ConnectionManager::sanitize(&mut backend).await {
                tracing::warn!(error = %e, "failed to sanitize connection");
            }
        });

        let q = query.trim().to_uppercase();

        match messages {
            Ok(msgs) => {
                let mut responses = if is_select_query(&q) {
                    Self::exec_query(msgs)
                } else {
                    Self::exec_command(msgs)
                };

                // Update transaction state
                if q == "BEGIN" || q.starts_with("BEGIN ") {
                    responses.push(Response::TransactionStart(Tag::new("BEGIN")));
                } else if q == "COMMIT" {
                    responses.push(Response::TransactionEnd(Tag::new("COMMIT")));
                } else if q == "ROLLBACK" || q.starts_with("ABORT") {
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

fn is_select_query(q: &str) -> bool {
    q.starts_with("SELECT")
        || q.starts_with("WITH")
        || q.starts_with("TABLE")
        || q.starts_with("VALUES")
}
