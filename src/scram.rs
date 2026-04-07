//! SCRAM-SHA-256 client authentication helper.

use crate::error::ProxyError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type HmacSha256 = Hmac<Sha256>;

const SHA256_NAME: &str = "SCRAM-SHA-256";

/// Perform SCRAM-SHA-256 authentication with the backend.
pub async fn scram_sha_256_authenticate<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), ProxyError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Generate nonce before first .await (ThreadRng is !Send)
    let client_nonce: String = {
        let mut rng = rand::thread_rng();
        (0..18)
            .map(|_| {
                let b: u8 = rng.gen();
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                    .chars()
                    .nth((b % 62) as usize)
                    .unwrap()
            })
            .collect()
    }; // rng dropped here, before first .await

    // Step 1: ClientFirst — GS2 header is "n,," (no channel binding)
    let client_first_bare = format!("n={},r={}", username, client_nonce);
    let client_first = format!("n,,{}", client_first_bare);
    send_sasl_initial_response(stream, SHA256_NAME, client_first.as_bytes()).await?;

    // Step 2: ServerFirst
    let server_first_raw = read_sasl_continue(stream).await?;
    let server_first_str = std::str::from_utf8(&server_first_raw)
        .map_err(|_| ProxyError::BackendAuth("invalid UTF-8 in server-first".into()))?;

    let sf = parse_server_first(server_first_str)?;

    if !sf.server_nonce.starts_with(&client_nonce) || sf.server_nonce.len() <= client_nonce.len() {
        return Err(ProxyError::BackendAuth(
            "server nonce doesn't start with client nonce".into(),
        ));
    }

    // Step 3: ClientFinal
    let client_final_without_proof = format!("c=biws,r={}", sf.server_nonce);

    let client_proof = compute_client_proof(
        password,
        client_first_bare.as_bytes(),
        server_first_str.as_bytes(),
        client_final_without_proof.as_bytes(),
        &sf.salt,
        sf.iteration_count,
    )?;

    let client_final_message = format!(",{}", client_proof);
    let full_client_final = format!("{}{}", client_final_without_proof, client_final_message);

    send_sasl_response(stream, full_client_final.as_bytes()).await?;

    // Step 4: ServerSignature — server sends AuthenticationSASLFinal (type 12)
    let server_final_raw = read_sasl_final(stream).await?;
    let server_final_str = std::str::from_utf8(&server_final_raw)
        .map_err(|_| ProxyError::BackendAuth("invalid UTF-8 in server-final".into()))?;

    if let Some(server_sig) = server_final_str.strip_prefix("v=") {
        let expected_sig = compute_server_signature(
            password,
            client_first_bare.as_bytes(),
            server_first_str.as_bytes(),
            client_final_without_proof.as_bytes(),
            &sf.salt,
            sf.iteration_count,
        )?;

        if server_sig != expected_sig {
            return Err(ProxyError::BackendAuth("server signature mismatch".into()));
        }
    } else if let Some(err_msg) = server_final_str.strip_prefix("e=") {
        return Err(ProxyError::BackendAuth(format!(
            "server error: {}",
            err_msg
        )));
    } else {
        return Err(ProxyError::BackendAuth(format!(
            "unexpected server-final: {}",
            server_final_str
        )));
    }

    tracing::debug!(username = %username, "SCRAM authentication successful");
    Ok(())
}

// ─── SCRAM internals ─────────────────────────────────────────────────────────

struct ServerFirst {
    salt: Vec<u8>,
    iteration_count: u32,
    server_nonce: String,
}

fn parse_server_first(s: &str) -> Result<ServerFirst, ProxyError> {
    let mut salt = None;
    let mut iter_count = None;
    let mut server_nonce = None;

    // The nonce in r= may contain commas, so split from the right: after the final ,s= or ,i=
    if let Some(r_pos) = s.find("r=") {
        // Extract r= value: from "r=" up to the last ",s=" or ",i="
        let after_r = &s[r_pos + 2..];
        let end = after_r
            .rfind(",s=")
            .or(after_r.rfind(",i="))
            .unwrap_or(after_r.len());
        server_nonce = Some(after_r[..end].to_string());
    }

    // Remaining attrs: s= and i= (after the nonce)
    if let Some(rest) = s.split(",s=").nth(1) {
        let parts: Vec<&str> = rest.splitn(2, ",i=").collect();
        salt = Some(base64_decode(parts[0]).map_err(|e| ProxyError::BackendAuth(e.to_string()))?);
        if parts.len() > 1 {
            iter_count = Some(
                parts[1]
                    .parse()
                    .map_err(|_| ProxyError::BackendAuth("invalid iteration count".into()))?,
            );
        }
    }
    // Handle i= without s= (fallback)
    if iter_count.is_none() {
        if let Some(rest) = s.split(",i=").nth(1) {
            iter_count = Some(
                rest.parse()
                    .map_err(|_| ProxyError::BackendAuth("invalid iteration count".into()))?,
            );
        }
    }

    Ok(ServerFirst {
        salt: salt.ok_or_else(|| ProxyError::BackendAuth("missing salt".into()))?,
        iteration_count: iter_count
            .ok_or_else(|| ProxyError::BackendAuth("missing iteration count".into()))?,
        server_nonce: server_nonce
            .ok_or_else(|| ProxyError::BackendAuth("missing server nonce".into()))?,
    })
}

fn compute_client_proof(
    password: &str,
    client_first_bare: &[u8],
    server_first: &[u8],
    client_final_message_without_proof: &[u8],
    salt: &[u8],
    iteration_count: u32,
) -> Result<String, ProxyError> {
    let normalized_password = normalize_password(password);
    let salted_password = hi(&normalized_password, salt, iteration_count)?;

    let client_key = hmac_sign(&salted_password, b"Client Key");
    let stored_key = sha256_hash(&client_key);

    let auth_message: Vec<u8> = join_bytes(&[
        client_first_bare,
        server_first,
        client_final_message_without_proof,
    ]);

    let client_signature = hmac_sign(&stored_key, &auth_message);

    let mut client_proof = vec![0u8; client_key.len()];
    for i in 0..client_key.len() {
        client_proof[i] = client_key[i] ^ client_signature[i];
    }

    Ok(base64_encode(&client_proof))
}

fn compute_server_signature(
    password: &str,
    client_first_bare: &[u8],
    server_first: &[u8],
    client_final_message_without_proof: &[u8],
    salt: &[u8],
    iteration_count: u32,
) -> Result<String, ProxyError> {
    let normalized_password = normalize_password(password);
    let salted_password = hi(&normalized_password, salt, iteration_count)?;

    let server_key = hmac_sign(&salted_password, b"Server Key");

    let auth_message: Vec<u8> = join_bytes(&[
        client_first_bare,
        server_first,
        client_final_message_without_proof,
    ]);

    let server_signature = hmac_sign(&server_key, &auth_message);

    Ok(base64_encode(&server_signature))
}

/// PBKDF2-HMAC-SHA256 key derivation.
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>, ProxyError> {
    let mut result = vec![0u8; 32];
    let mut u = vec![0u8; 32];

    let mut mac =
        HmacSha256::new_from_slice(password).map_err(|e| ProxyError::BackendAuth(e.to_string()))?;
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    u.copy_from_slice(&mac.finalize().into_bytes());
    result.copy_from_slice(&u); // XOR in U1 (result is zeroed, so copy = XOR)

    for _ in 2..=iterations {
        let mut mac = HmacSha256::new_from_slice(password)
            .map_err(|e| ProxyError::BackendAuth(e.to_string()))?;
        mac.update(&u);
        u.copy_from_slice(&mac.finalize().into_bytes());
        for i in 0..32 {
            result[i] ^= u[i];
        }
    }

    Ok(result)
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    Sha256::new().chain_update(data).finalize().to_vec()
}

fn normalize_password(password: &str) -> Vec<u8> {
    // RFC 5802: normalize according to SASLprep profile
    // For simplicity, we use the password as-is (Postgres SCRAM accepts this)
    password.as_bytes().to_vec()
}

/// Join byte slices with a separator.
fn join_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let sep = b',';
    let total: usize = parts.iter().map(|p| p.len()).sum::<usize>() + parts.len().saturating_sub(1);
    let mut result = Vec::with_capacity(total);
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            result.push(sep);
        }
        result.extend_from_slice(part);
    }
    result
}

fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    BASE64
        .decode(s)
        .map_err(|_| "invalid base64")
}

// ─── Wire framing helpers ────────────────────────────────────────────────────

async fn send_sasl_initial_response<S>(
    stream: &mut S,
    mechanism: &str,
    initial_response: &[u8],
) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'p');
    // length = 4 (self) + mechanism + null + Int32(initial_response_len) + initial_response
    let response_len = 4 + mechanism.len() + 1 + 4 + initial_response.len();
    buf.extend_from_slice(&(response_len as u32).to_be_bytes());
    buf.extend_from_slice(mechanism.as_bytes());
    buf.push(0);
    if initial_response.is_empty() {
        buf.extend_from_slice(&(-1i32).to_be_bytes());
    } else {
        buf.extend_from_slice(&(initial_response.len() as i32).to_be_bytes());
        buf.extend_from_slice(initial_response);
    }
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_sasl_response<S>(stream: &mut S, data: &[u8]) -> Result<(), ProxyError>
where
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    buf.push(b'p');
    let len: u32 = 4 + data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_sasl_auth_message<S>(
    stream: &mut S,
    expected_type: u32,
) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    let mut type_buf = [0u8; 1];
    stream.read_exact(&mut type_buf).await?;
    if type_buf[0] != b'R' {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected SASL auth message (R), got {:02x}",
            type_buf[0]
        )));
    }
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    let mut body = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut body).await?;
    let auth_type = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if auth_type != expected_type {
        return Err(ProxyError::ProtocolViolation(format!(
            "expected SASL auth type {}, got {}",
            expected_type, auth_type
        )));
    }
    Ok(body[4..].to_vec())
}

/// Read AuthenticationSASLContinue (type 11) from the backend.
async fn read_sasl_continue<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    read_sasl_auth_message(stream, 11).await
}

/// Read AuthenticationSASLFinal (type 12) from the backend.
async fn read_sasl_final<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: AsyncReadExt + Unpin,
{
    read_sasl_auth_message(stream, 12).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let cases: &[&[u8]] = &[b"a", b"ab", b"abc", b"Hello, World!", b"\x00\xff\xfe\xfd"];
        for case in cases {
            let encoded = base64_encode(case);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded.as_slice(), *case, "roundtrip failed for {:?}", case);
        }
        // Also test empty explicitly
        let encoded = base64_encode(b"");
        assert_eq!(base64_decode(&encoded).unwrap(), b"");
    }

    #[test]
    fn test_parse_server_first_valid() {
        let s =
            "r=fyko+d2lbbFgONe9WqKkE2qtVdgo,+5qdLY9Rw=,s=QSXCRQD6Yt6AS+kWSMEpqhGkg5e/klE+,i=4096";
        let sf = parse_server_first(s).unwrap();
        assert_eq!(sf.server_nonce, "fyko+d2lbbFgONe9WqKkE2qtVdgo,+5qdLY9Rw=");
        assert_eq!(sf.iteration_count, 4096);
    }

    #[test]
    fn test_parse_server_first_missing_fields() {
        assert!(parse_server_first("r=nonce").is_err());
        assert!(parse_server_first("s=salt").is_err());
        assert!(parse_server_first("i=4096").is_err());
    }

    #[test]
    fn test_sha256_hash_known() {
        use sha2::Digest;
        // Known SHA256 of "test"
        let result = sha256_hash(b"test");
        let expected = Sha256::digest(b"test");
        assert_eq!(result, expected.to_vec());
    }

    #[test]
    fn test_hmac_sign_deterministic() {
        let sig1 = hmac_sign(b"key", b"data");
        let sig2 = hmac_sign(b"key", b"data");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 32); // SHA256 output = 32 bytes
    }

    #[test]
    fn test_hi_includes_first_iteration() {
        // Regression test: hi() must XOR in U1 (the first HMAC iteration).
        // Without this, only iterations 2..n are XORed, giving a wrong result.
        // Test vector from RFC 6070 / test vectors for PBKDF2-SHA256:
        // password="password", salt="salt", c=4096, DK=120fb06c...
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let result = hi(password, salt, iterations).expect("hi should succeed");
        // RFC 6070 test vector: PBKDF2-SHA256("password", "salt", 4096)
        assert_eq!(
            &result[..4],
            &[0xc5, 0xe4, 0x78, 0xd5],
            "hi() must XOR in U1 (first iteration); without it the result is wrong"
        );
    }

}
