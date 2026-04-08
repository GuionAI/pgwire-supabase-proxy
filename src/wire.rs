//! Minimal Postgres wire protocol message codec.
//!
//! This module implements the subset of the Postgres wire protocol needed for
//! the byte-forward proxy: client auth (JWT), backend auth (SCRAM), and
//! handshake message exchange. After handshake, all bytes are forwarded transparently.

use crate::error::ProxyError;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─── Client → Proxy messages ─────────────────────────────────────────────────

/// Represents a parsed StartupMessage.
#[derive(Debug)]
#[allow(dead_code)]
pub struct StartupMessage {
    pub protocol_version: u32,
    pub params: HashMap<String, String>,
}

/// Parse the body of a StartupMessage (length already read).
pub fn parse_startup_body(_msg_len: u32, buf: &[u8]) -> Result<StartupMessage, ProxyError> {
    let protocol_version = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // Parse null-terminated key=value pairs
    let mut params = HashMap::new();
    let mut i = 4;
    while i + 1 < buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 {
            break; // Final null terminator
        }
        // Read key
        let key_start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        let key = std::str::from_utf8(&buf[key_start..i])
            .map_err(|_| ProxyError::ProtocolViolation("invalid UTF-8 in startup key".into()))?
            .to_string();
        i += 1;
        if i >= buf.len() {
            break;
        }

        // Read value
        let value_start = i;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        let value = std::str::from_utf8(&buf[value_start..i])
            .map_err(|_| ProxyError::ProtocolViolation("invalid UTF-8 in startup value".into()))?
            .to_string();
        i += 1;

        params.insert(key, value);
    }

    Ok(StartupMessage {
        protocol_version,
        params,
    })
}

/// Read a PasswordMessage from the client.
/// Wire format: Byte1('p') + Int32(len) + String(password, null-terminated)
pub async fn read_password_message<S>(stream: &mut S) -> Result<String, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut type_buf = [0u8; 1];
    stream.read_exact(&mut type_buf).await?;
    if type_buf[0] != b'p' {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected PasswordMessage ('p'), got 0x{:02x}",
            type_buf[0]
        )));
    }
    let len = read_message_length(stream).await?;
    let mut buf = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut buf).await?;
    // Strip null terminator
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let password = std::str::from_utf8(&buf[..end])
        .map_err(|_| ProxyError::ProtocolViolation("invalid UTF-8 in password".into()))?
        .to_string();
    Ok(password)
}

// ─── Proxy → Client messages ────────────────────────────────────────────────

/// Write AuthenticationCleartextPassword (R, type=3).
pub async fn write_authentication_cleartext_password<S>(stream: &mut S) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 9]; // 'R' + len(4) + auth_type(4)
    buf[0] = b'R';
    buf[1..5].copy_from_slice(&8u32.to_be_bytes()); // length = 4 (self) + 4 (auth_type) = 8
    buf[5..9].copy_from_slice(&3u32.to_be_bytes());
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Write AuthenticationOk (R, type=0).
pub async fn write_authentication_ok<S>(stream: &mut S) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 9];
    buf[0] = b'R';
    buf[1..5].copy_from_slice(&8u32.to_be_bytes()); // length = 4 (self) + 4 (auth_type) = 8
    buf[5..9].copy_from_slice(&0u32.to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}

/// Write a ParameterStatus (S) message.
pub async fn write_parameter_status<S>(
    stream: &mut S,
    key: &str,
    value: &str,
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'S');
    let len_pos = buf.len();
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(key.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
    // length = buf.len() - 1 (excludes the type byte 'S')
    let len = (buf.len() - 1) as u32;
    buf[len_pos..len_pos + 4].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}

/// Write BackendKeyData (K).
pub async fn write_backend_key_data<S>(
    stream: &mut S,
    process_id: i32,
    secret_key: i32,
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 13];
    buf[0] = b'K';
    buf[1..5].copy_from_slice(&12u32.to_be_bytes());
    buf[5..9].copy_from_slice(&(process_id as u32).to_be_bytes());
    buf[9..13].copy_from_slice(&(secret_key as u32).to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}

/// Write ReadyForQuery (Z) with transaction status byte.
pub async fn write_ready_for_query<S>(stream: &mut S, status: u8) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 6];
    buf[0] = b'Z';
    buf[1..5].copy_from_slice(&5u32.to_be_bytes());
    buf[5] = status;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Write an ErrorResponse (E).
pub async fn write_error_response<S>(
    stream: &mut S,
    sqlstate: &str,
    message: &str,
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'E');
    let len_pos = buf.len();
    buf.extend_from_slice(&[0, 0, 0, 0]);

    // Field: Severity
    buf.push(b'S');
    buf.extend_from_slice(b"FATAL");
    buf.push(0);
    // Field: SQLSTATE
    buf.push(b'C');
    buf.extend_from_slice(sqlstate.as_bytes());
    buf.push(0);
    // Field: Message
    buf.push(b'M');
    buf.extend_from_slice(message.as_bytes());
    buf.push(0);
    // Terminator
    buf.push(0);

    // length = buf.len() - 1 (excludes the type byte 'E')
    let len = (buf.len() - 1) as u32;
    buf[len_pos..len_pos + 4].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

// ─── Proxy → Backend messages ────────────────────────────────────────────────

/// Write a StartupMessage to the backend.
pub async fn write_startup_message<S>(
    stream: &mut S,
    params: &HashMap<String, String>,
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut body = Vec::new();
    body.extend_from_slice(&196608u32.to_be_bytes());
    for (key, value) in params {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);

    let mut msg = Vec::new();
    let len: u32 = 4 + body.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&body);

    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Write a PasswordMessage ('p') to the backend.
pub async fn write_password_message<S>(stream: &mut S, password: &str) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'p');
    let len: u32 = 4 + password.len() as u32 + 1;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(password.as_bytes());
    buf.push(0);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Write a SASL InitialResponse ('p' message) carrying the chosen mechanism
/// name and the client-first message body.
///
/// Wire format: `'p' | u32 length | mechanism bytes | 0u8 | i32 initial_len | initial bytes`
/// (initial_len = -1 if `initial` is empty.)
pub async fn write_sasl_initial_response<S>(
    stream: &mut S,
    mechanism: &str,
    initial: &[u8],
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(1 + 4 + mechanism.len() + 1 + 4 + initial.len());
    buf.push(b'p');
    let body_len: u32 = (4 + mechanism.len() + 1 + 4 + initial.len()) as u32;
    buf.extend_from_slice(&body_len.to_be_bytes());
    buf.extend_from_slice(mechanism.as_bytes());
    buf.push(0);
    if initial.is_empty() {
        buf.extend_from_slice(&(-1i32).to_be_bytes());
    } else {
        buf.extend_from_slice(&(initial.len() as i32).to_be_bytes());
        buf.extend_from_slice(initial);
    }
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Write a SASL Response ('p' message) carrying the client-final message body.
///
/// Wire format: `'p' | u32 length | data bytes`
pub async fn write_sasl_response<S>(stream: &mut S, data: &[u8]) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(1 + 4 + data.len());
    buf.push(b'p');
    let body_len: u32 = (4 + data.len()) as u32;
    buf.extend_from_slice(&body_len.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a backend AuthenticationRequest ('R') message and assert its auth_type
/// matches `expected_type`. Returns the body bytes after the auth_type field.
///
/// Used to read AuthenticationSASLContinue (type=11), AuthenticationSASLFinal
/// (type=12), and AuthenticationOk (type=0) during SCRAM exchange.
pub async fn read_sasl_auth_message<S>(
    stream: &mut S,
    expected_type: u32,
) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await?;
    if tag[0] != b'R' {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected AuthenticationRequest (R), got {:02x}",
            tag[0]
        )));
    }
    let len = read_message_length(stream).await?;
    let mut body = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut body).await?;
    if body.len() < 4 {
        return Err(ProxyError::ProtocolViolation(
            "AuthenticationRequest body too short".into(),
        ));
    }
    let auth_type = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if auth_type != expected_type {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected SASL auth type {}, got {}",
            expected_type, auth_type
        )));
    }
    Ok(body[4..].to_vec())
}

/// Write a Query message ('Q').
pub async fn write_query<S>(stream: &mut S, sql: &str) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'Q');
    let len: u32 = 4 + sql.len() as u32 + 1;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

// ─── Backend → Proxy messages ───────────────────────────────────────────────

async fn read_message_length<S>(stream: &mut S) -> Result<u32, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    Ok(u32::from_be_bytes(len_buf))
}

/// Authentication method received from the backend.
#[derive(Debug)]
#[allow(dead_code)]
pub enum AuthMethod {
    Ok,
    CleartextPassword,
    Md5Password { salt: [u8; 4] },
    Sasl { mechanisms: Vec<String> },
}

/// Read the authentication request from the backend.
pub async fn read_authentication_method<S>(stream: &mut S) -> Result<AuthMethod, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut type_byte = [0u8; 1];
    stream.read_exact(&mut type_byte).await?;
    if type_byte[0] != b'R' {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected AuthenticationRequest (R), got {:02x}",
            type_byte[0]
        )));
    }

    let len = read_message_length(stream).await?;
    let mut body = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut body).await?;

    let auth_type = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    match auth_type {
        0 => Ok(AuthMethod::Ok),
        3 => Ok(AuthMethod::CleartextPassword),
        5 => {
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&body[4..8]);
            Ok(AuthMethod::Md5Password { salt })
        }
        10 => {
            let mechanisms = std::str::from_utf8(&body[4..])
                .map_err(|_| ProxyError::ProtocolViolation("invalid SASL mechanism list".into()))?
                .trim_end_matches('\0')
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            Ok(AuthMethod::Sasl { mechanisms })
        }
        _ => Err(ProxyError::ProtocolViolation(format!(
            "unknown auth type: {}",
            auth_type
        ))),
    }
}

/// Backend message types we care about during handshake drain.
#[derive(Debug)]
#[allow(dead_code)]
pub enum BackendMessage {
    ReadyForQuery {
        transaction_status: u8,
    },
    ParameterStatus {
        key: String,
        value: String,
    },
    BackendKeyData {
        process_id: i32,
        secret_key: i32,
    },
    ErrorResponse {
        severity: Option<String>,
        code: Option<String>,
        message: String,
    },
    Unknown {
        tag: u8,
    },
}

/// Read a backend message (during handshake drain phase).
pub async fn read_backend_message<S>(stream: &mut S) -> Result<BackendMessage, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut type_buf = [0u8; 1];
    stream.read_exact(&mut type_buf).await?;
    let tag = type_buf[0];

    let len = read_message_length(stream).await?;
    let mut body = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut body).await?;

    match tag {
        b'Z' => {
            let status = body.first().copied().unwrap_or(b'I');
            Ok(BackendMessage::ReadyForQuery {
                transaction_status: status,
            })
        }
        b'S' => {
            let (key, rest) = split_null(&body);
            let (value, _) = split_null(rest);
            Ok(BackendMessage::ParameterStatus {
                key: String::from_utf8_lossy(key).to_string(),
                value: String::from_utf8_lossy(value).to_string(),
            })
        }
        b'K' => {
            let process_id = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let secret_key = i32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            Ok(BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            })
        }
        b'E' => {
            let mut severity = None;
            let mut code = None;
            let mut message = String::new();
            let mut i = 0;
            while i < body.len() {
                let field_type = body[i];
                i += 1;
                if field_type == 0 {
                    break;
                }
                let rest = &body[i..];
                let (value, rest2) = split_null(rest);
                i += body.len() - rest2.len();
                let value_str = String::from_utf8_lossy(value).to_string();
                match field_type {
                    b'S' => severity = Some(value_str),
                    b'C' => code = Some(value_str),
                    b'M' => message = value_str,
                    _ => {}
                }
            }
            Ok(BackendMessage::ErrorResponse {
                severity,
                code,
                message,
            })
        }
        _ => {
            tracing::warn!(tag, "unknown backend message during handshake");
            Ok(BackendMessage::Unknown { tag })
        }
    }
}

fn split_null(slice: &[u8]) -> (&[u8], &[u8]) {
    match slice.iter().position(|&b| b == 0) {
        Some(pos) => (&slice[..pos], &slice[pos + 1..]),
        None => (slice, &[][..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_sasl_initial_response_layout() {
        let mut buf = Vec::new();
        write_sasl_initial_response(&mut buf, "SCRAM-SHA-256", b"hello")
            .await
            .unwrap();
        // Expected: 'p' | u32(4 + 13 + 1 + 4 + 5) = 27 | "SCRAM-SHA-256" | 0 | i32(5) | "hello"
        assert_eq!(buf[0], b'p');
        assert_eq!(&buf[1..5], &27u32.to_be_bytes());
        assert_eq!(&buf[5..18], b"SCRAM-SHA-256");
        assert_eq!(buf[18], 0);
        assert_eq!(&buf[19..23], &5i32.to_be_bytes());
        assert_eq!(&buf[23..28], b"hello");
    }

    #[tokio::test]
    async fn write_sasl_response_layout() {
        let mut buf = Vec::new();
        write_sasl_response(&mut buf, b"final-msg").await.unwrap();
        // Expected: 'p' | u32(4 + 9) = 13 | "final-msg"
        assert_eq!(buf[0], b'p');
        assert_eq!(&buf[1..5], &13u32.to_be_bytes());
        assert_eq!(&buf[5..14], b"final-msg");
    }

    #[tokio::test]
    async fn write_sasl_initial_response_empty_initial() {
        let mut buf = Vec::new();
        write_sasl_initial_response(&mut buf, "SCRAM-SHA-256", b"")
            .await
            .unwrap();
        // Expected: 'p' | u32(4 + 13 + 1 + 4) = 22 | "SCRAM-SHA-256" | 0 | i32(-1)
        assert_eq!(buf[0], b'p');
        assert_eq!(&buf[1..5], &22u32.to_be_bytes());
        assert_eq!(&buf[5..18], b"SCRAM-SHA-256");
        assert_eq!(buf[18], 0);
        assert_eq!(&buf[19..23], &(-1i32).to_be_bytes());
        assert_eq!(buf.len(), 23);
    }
}
