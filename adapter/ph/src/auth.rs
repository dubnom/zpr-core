//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  Also includes other "auth" related functionality.

use aws_lc_rs::signature::RsaKeyPair;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use reqwest::StatusCode;
use reqwest::header;
use reqwest::redirect::Policy;
use reqwest::tls::Certificate;

use base64::prelude::*;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::Certificate as X509Certificate;
use zpr_utils::rsa_sign::{load_rsa_key, sign_rsa_key};

use crate::pki;

/// When a node signs a challenge for an adapter it uses this sort of key.
pub const AUTH_KEY_SIZE_BYTES: usize = 32; // blake3 256bit key

/// "self signed" blob type
pub const BLOB_TYPE_SS: &str = "SS";

/// Auth Code blob type
pub const BLOB_TYPE_AC: &str = "AC";

/// When checking a challenge returned to a node by an adapter, it may
/// be no older than this.
pub const MAX_BLOB_AGE_SECONDS: u64 = 120; // 2 minutes

const BAS_TLS_HOST: &str = "auth.zpr";

/// This is the data payload in a [zdp::PacketType::InitAuthenticationRequest] packet.
#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Default)]
#[repr(packed)]
pub struct ZdpInitAuthenticationPayload {
    /// 8 bytes random data
    pub nonce: [u8; 8],

    /// Unix time seconds, big endian
    pub ctime: U64,

    /// blake3 hmac over nonce and ctime
    pub hmac: [u8; 32],
}

// Implement our own Debug to format the buffers in human friendly way.
impl std::fmt::Debug for ZdpInitAuthenticationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nonce_str = self
            .nonce
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        let hmac_str = self
            .hmac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        write!(
            f,
            "ZdpInitAuthenticationPayload {{ nonce: [{}], ctime: {}, hmac: [{}] }}",
            nonce_str,
            self.ctime.get(),
            hmac_str,
        )
    }
}

/// The "self signed" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug)]
pub struct ZdpSelfSignedBlob {
    pub blob_type: String, // "SS"
    pub ts: u64,
    pub cn: String,
    pub challenge: String, // byte buffer, base64 encoded
    pub sig: String,       // byte buffer, base64 encoded
}

/// The "Auth Code" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZdpAuthCodeBlob {
    pub blob_type: String, // "AC"
    pub code: String,
    pub pkce: String,
    pub client_id: String,
    pub asa: String,
}

/// Enum used to return different blob types based on their blob_type field.
#[allow(dead_code)]
#[derive(Debug)]
pub enum AuthBlob {
    SelfSigned(ZdpSelfSignedBlob),
    AuthCode(ZdpAuthCodeBlob),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("OpenSSL Error: {0}")]
    OpenSSLError(String),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Format error: {0}")]
    FormatError(String),

    #[error("Invalid Base64: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Invalid HMAC")]
    InvalidHmac,

    #[error("Challenge Too Old")]
    ChallengeTooOld,

    #[error("Authentication Error: {0}")]
    AuthError(String),
}

#[derive(Debug, Clone)]
pub struct RsaBootstrapAuth {
    pkey: Arc<RsaKeyPair>,
    cn: String,
}

/// OAuthRsa holds small amount of state needed to talk to a
/// zpr-oauthrsa authentication service.
#[derive(Debug, Clone)]
pub struct OAuthRsa {
    client_id: String,
    private_key: Arc<RsaKeyPair>,
    tls_ca: Certificate,
}

impl ZdpAuthCodeBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }
}

impl ZdpSelfSignedBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }

    /// The `challenge` field in the blob is a base64 encoded [zdp::ZdpInitAuthenticationPayload].
    /// This extracts that data and checks that:
    ///   - If the peer presented a certificate during keying, the CN in that
    ///     certificate matches the CN in the blob. Adapters using self-generated
    ///     keys send no certificate (`peer_cert` is `None`); there is then no
    ///     cert CN to bind to, so this check is skipped and the blob CN is
    ///     authenticated solely by the visa service's RSA signature check.
    ///   - The HMAC in the blob is valid for the provided `key`.
    ///   - The blob is not older than `MAX_BLOB_AGE_SECONDS`.
    pub fn verify_blob_challenge(
        &self,
        peer_cert: Option<&X509Certificate>,
        key: &[u8; AUTH_KEY_SIZE_BYTES],
    ) -> Result<(), AuthError> {
        if let Some(peer_cert) = peer_cert {
            if let Some(link_cn) = pki::common_name(peer_cert) {
                if link_cn != self.cn {
                    return Err(AuthError::FormatError(format!(
                        "CN mismatch: expected {link_cn} found {}",
                        self.cn
                    )));
                }
            } else {
                return Err(AuthError::FormatError("no CN in peer cert".to_string()));
            }
        }

        let payload_bytes = BASE64_STANDARD.decode(self.challenge.clone())?;
        if payload_bytes.len() != size_of::<ZdpInitAuthenticationPayload>() {
            return Err(AuthError::FormatError(format!(
                "challenge size is incorrect"
            )));
        }
        let zpayload = match ZdpInitAuthenticationPayload::read_from_bytes(&payload_bytes) {
            Ok(zpayload) => zpayload,
            Err(e) => {
                return Err(AuthError::FormatError(format!(
                    "failed to deserialize ZdpInitAuthenticationPayload: {e}"
                )));
            }
        };

        let hash_ok = {
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&zpayload.nonce);
            hasher.update(&zpayload.ctime.to_bytes());
            let computed_hmac = hasher.finalize();
            let presented_hmac = blake3::Hash::from_bytes(zpayload.hmac);
            computed_hmac == presented_hmac
        };

        if !hash_ok {
            return Err(AuthError::InvalidHmac);
        }

        // Now can check age of blob.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        if now > zpayload.ctime.get() + MAX_BLOB_AGE_SECONDS {
            return Err(AuthError::ChallengeTooOld);
        }

        Ok(())
    }
}

impl ZdpInitAuthenticationPayload {
    pub fn new(key: &[u8; AUTH_KEY_SIZE_BYTES]) -> Self {
        let ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        let be_time = ctime.to_be_bytes();
        let mut nonce = [0u8; 8];
        aws_lc_rs::rand::fill(&mut nonce).expect("failed to generate random bytes for nonce");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&nonce);
        hasher.update(&be_time);
        let hmac = hasher.finalize();
        ZdpInitAuthenticationPayload {
            nonce,
            ctime: ctime.into(),
            hmac: hmac.into(),
        }
    }
}

/// Decode a blob string into a [AuthBlob] object.
/// The blob string is base64 encoded JSON which contains a "blob_type" field.
pub fn decode_blob(blob_str: &str) -> Result<AuthBlob, AuthError> {
    let json_txt = BASE64_STANDARD.decode(blob_str)?;

    let jobj: Value = serde_json::from_slice(&json_txt)?;
    let blob_type = jobj.get("blob_type").ok_or_else(|| {
        AuthError::FormatError(format!("missing blob_type field in blob: {}", blob_str))
    })?;

    match blob_type.as_str() {
        Some(BLOB_TYPE_SS) => {
            let ss_blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&json_txt)?;
            Ok(AuthBlob::SelfSigned(ss_blob))
        }
        Some(BLOB_TYPE_AC) => {
            let ac_blob = serde_json::from_slice::<ZdpAuthCodeBlob>(&json_txt)?;
            Ok(AuthBlob::AuthCode(ac_blob))
        }
        _ => Err(AuthError::FormatError(format!(
            "unknown blob_type: {:?}",
            blob_type
        ))),
    }
}

/// Implementes BootstrapAuth using our RSA signature scheme.
impl RsaBootstrapAuth {
    /// Create a new RsaBootstrapAuth object.
    /// The `cn` is the common name of the actor.
    /// The `rsa_keyfile` is the path to the PEM file containing the RSA private key.
    /// The visa service (policy) must be configured with the corresponding public key.
    pub fn new(cn: &str, rsa_keyfile: &Path) -> Result<Self, AuthError> {
        let pemdata = std::fs::read(rsa_keyfile)?;
        let pkey = Arc::new(
            load_rsa_key(&pemdata)
                .map_err(|e| AuthError::OpenSSLError(format!("Failed to load RSA key: {}", e)))?,
        );
        Ok(RsaBootstrapAuth {
            pkey,
            cn: cn.to_string(),
        })
    }

    /// The returned string is a "SelfSignedBlob" object serialized to JSON and then base64 encoded.
    ///
    /// The signature here is created by signing:
    ///  - the current timestamp (in seconds since the epoch)
    ///  - the common name (cn) of the actor
    ///  - the challenge from the ZDP server, which is the (nonce, ctime, hmac) all concatentated
    ///    together in a byte buffer.
    pub fn authenticate(
        &self,
        payload: &ZdpInitAuthenticationPayload,
    ) -> Result<String, AuthError> {
        // TODO: Check the payload.flags?
        // TODO: This could be an impl function in zdp
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let mut data = Vec::new();
        data.extend_from_slice(&ts.to_be_bytes());
        data.extend_from_slice(self.cn.as_bytes());
        data.extend_from_slice(&challenge);

        let signature = sign_rsa_key(&self.pkey, &data);

        let sig_str = BASE64_STANDARD.encode(&signature);

        let blob = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts,
            cn: self.cn.clone(),
            challenge: BASE64_STANDARD.encode(&challenge),
            sig: sig_str,
        };
        Ok(blob.encode())
    }

    #[cfg(test)]
    pub fn cn(&self) -> &str {
        &self.cn
    }
}

/// Response json object to initial auth request from an actor
/// from a zpr-oauthrsa authentication service.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct PreauthResp {
    nonce: String,
}

/// Request json object from an actor to a zpr-oauthrsa authentication service.
/// Includes the nonce from preauth step and the payload which is the RSA
/// signature of the nonce.  The `client_id` must match one known to the
/// authentication service (for now we are using CNs here).
#[derive(Serialize, Debug)]
struct AuthReq {
    client_id: String,
    nonce: String,
    payload: String,
}

/// Implements the ZPR oauthrsa protocol.
///
/// Works like this:
/// - Adapter sends a GET request to /preauthorize with form encoded params in query string
///   of (response_type, client_id, scope, state).
/// - Service returns json object with a "nonce" field, a base64 encoded byte buffer.
/// - Adapter sends a POST to /authorize with a json object having fields: (client_id, nonce, payload).
///   `nonce` is copied from the service response.  `payload` is the base64 encoded signature of
///   the nonce using the adapters private RSA key.  The `client_id` (in the case of BAS) is
///   the CN of the adapter.
/// - The service response with an auth-code which will be part of a redirect `location` header.
///   The format is `https://auth.zpr?code=<CODE>`).
///
/// Once we have an auth-code back from the authentication service we can construct the
/// auth-code blob as:
/// - blob_type: "AC"
/// - code: "<CODE>" (the auth-code)
/// - pkce: empty for now
/// - client_id: the CN of the adapter
/// - asa: The ZPR address of the authentication service
///
/// The blob should be passed to the Node which will forward it to the visa service.
impl OAuthRsa {
    /// Create a new OAuthRsa object.
    /// - `client_id` is the adapter CN
    /// - `private_key` is the RSA private key used to sign the nonce
    pub fn new(client_id: &str, private_key: Arc<RsaKeyPair>, tls_ca: Certificate) -> Self {
        OAuthRsa {
            client_id: client_id.to_string(),
            private_key,
            tls_ca,
        }
    }

    /// Performs the two calls to the authentication service and the signing of the nonce.
    /// On success returns the auth-code blob.
    /// - `service_addr` is the address of the authentication service
    /// - `tls_cert` is the TLS certificate used by the authentication service
    pub async fn authenticate(
        &self,
        service_addr: SocketAddr,
        local_addr: std::net::IpAddr,
    ) -> Result<ZdpAuthCodeBlob, AuthError> {
        let nonce_buf = self.preauthorize(service_addr, local_addr).await?;

        let signature = sign_rsa_key(&self.private_key, &nonce_buf);

        let auth_code = self
            .authorize(service_addr, local_addr, &nonce_buf, &signature)
            .await?;

        Ok(ZdpAuthCodeBlob {
            blob_type: BLOB_TYPE_AC.to_string(),
            code: auth_code,
            pkce: String::new(),
            client_id: self.client_id.clone(),
            asa: service_addr.to_string(),
        })
    }

    /// Call preauthorize function on authentication service.
    /// Returns the nonce.
    async fn preauthorize(
        &self,
        service_addr: SocketAddr,
        local_addr: std::net::IpAddr,
    ) -> Result<Vec<u8>, AuthError> {
        // See https://github.com/org-zpr/zpr-core/issues/861
        let client = self.client(service_addr, local_addr)?;
        let resp = client
            .get(self.url(service_addr, "/preauthorize"))
            .query(&[("response_type", "code"), ("client_id", &self.client_id)])
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send request: {}", e)))?;

        if resp.status() != StatusCode::OK {
            return Err(AuthError::AuthError(format!(
                "preauthorize returned {}",
                resp.status()
            )));
        }
        let pa_resp: PreauthResp = resp
            .json()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to parse response: {}", e)))?;

        let nonce = BASE64_STANDARD.decode(pa_resp.nonce.as_bytes())?;
        if !(32..=256).contains(&nonce.len()) {
            return Err(AuthError::FormatError(
                "preauthorize nonce must contain 32 to 256 bytes".into(),
            ));
        }
        Ok(nonce)
    }

    /// Call the authorize function on the authentication service.
    /// Returns the auth-code.
    async fn authorize(
        &self,
        service_addr: SocketAddr,
        local_addr: std::net::IpAddr,
        nonce: &[u8],
        payload: &[u8],
    ) -> Result<String, AuthError> {
        let authreq = AuthReq {
            client_id: self.client_id.clone(),
            nonce: BASE64_STANDARD.encode(nonce),
            payload: BASE64_STANDARD.encode(payload),
        };

        // Note client set to NOT follow redirects since that is how we get our response.
        let client = self.client(service_addr, local_addr)?;
        let resp = client
            .post(self.url(service_addr, "/authorize"))
            .json(&authreq)
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send POST request: {}", e)))?;

        // Expect status code FOUND
        if resp.status() != StatusCode::FOUND {
            return Err(AuthError::AuthError(format!(
                "failed to authorize: {}",
                resp.status()
            )));
        }

        // Now extract the auth-code from the location header.
        let location = resp.headers().get(header::LOCATION).ok_or_else(|| {
            AuthError::AuthError("authorize response has no location header".into())
        })?;
        let location = location
            .to_str()
            .map_err(|_| AuthError::AuthError("authorize location header is invalid".into()))?;
        parse_auth_code_location(location)
    }

    fn client(
        &self,
        service_addr: SocketAddr,
        local_addr: std::net::IpAddr,
    ) -> Result<reqwest::Client, AuthError> {
        reqwest::ClientBuilder::new()
            .local_address(local_addr)
            .add_root_certificate(self.tls_ca.clone())
            .resolve_to_addrs(BAS_TLS_HOST, &[service_addr])
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AuthError::AuthError(format!("failed to configure BAS HTTPS client: {e}")))
    }

    fn url(&self, service_addr: SocketAddr, path: &str) -> String {
        format!("https://{BAS_TLS_HOST}:{}{path}", service_addr.port())
    }
}

fn parse_auth_code_location(location: &str) -> Result<String, AuthError> {
    let location = url::Url::parse(location)
        .map_err(|_| AuthError::AuthError("authorize returned an invalid redirect URL".into()))?;
    if location.scheme() != "https"
        || location.host_str() != Some(BAS_TLS_HOST)
        || location.port_or_known_default() != Some(443)
        || location.path() != "/"
        || location.username() != ""
        || location.password().is_some()
        || location.fragment().is_some()
    {
        return Err(AuthError::AuthError(
            "authorize returned an untrusted redirect URL".into(),
        ));
    }
    let mut pairs = location.query_pairs();
    let Some((key, code)) = pairs.next() else {
        return Err(AuthError::AuthError(
            "authorize redirect contains no code".into(),
        ));
    };
    if key != "code"
        || code.is_empty()
        || code.len() > 256
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        || pairs.next().is_some()
    {
        return Err(AuthError::AuthError(
            "authorize redirect contains an invalid code".into(),
        ));
    }
    Ok(code.into_owned())
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };

    fn test_tls_material(host: &str) -> (Certificate, Vec<u8>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        let tls_ca = Certificate::from_der(&der).unwrap();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (tls_ca, der, private_key)
    }

    async fn start_test_auth_server(
        cert: Vec<u8>,
        private_key: PrivateKeyDer<'static>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.into()], private_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let Ok(count) = stream.read(&mut buffer).await else {
                    return;
                };
                if count == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.len() > 8192 {
                    return;
                }
            }
            let body = format!(r#"{{"nonce":"{}"}}"#, BASE64_STANDARD.encode([1u8; 32]));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, task)
    }

    fn test_oauth(tls_ca: Certificate) -> OAuthRsa {
        let mut key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        key_path.push("tests");
        key_path.push("data");
        key_path.push("rsa-key.pem");
        let key = load_rsa_key(&std::fs::read(key_path).unwrap()).unwrap();
        OAuthRsa::new("adapter.example", Arc::new(key), tls_ca)
    }

    #[test]
    fn test_rsa_bootstrap_auth() {
        let mut keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keypath.push("tests");
        keypath.push("data");
        keypath.push("rsa-key.pem");

        let cn = "test.cn.zpr";
        let bs = RsaBootstrapAuth::new(cn, &keypath).unwrap();

        let ctime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let payload = ZdpInitAuthenticationPayload {
            nonce: [42u8; 8],
            ctime: ctime.into(),
            hmac: [24u8; 32],
        };

        let blob = bs.authenticate(&payload).unwrap();
        assert!(!blob.is_empty());

        let blob_json = BASE64_STANDARD.decode(&blob).unwrap();
        let blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&blob_json).unwrap();

        assert_eq!(blob.blob_type, BLOB_TYPE_SS);
        assert!(blob.ts > 0);
        assert!(blob.ts >= ctime);
        assert_eq!(blob.cn, cn);

        let challenge_buffer = BASE64_STANDARD.decode(&blob.challenge).unwrap();
        assert_eq!(challenge_buffer.len(), 48);
        {
            // Challenge buffer layout:
            // [ 0..8 ] nonce
            // [ 8..16] ctime
            // [16..48] hmac
            for i in 0..8 {
                assert_eq!(challenge_buffer[i], payload.nonce[i]);
                assert_eq!(challenge_buffer[i + 8], payload.ctime.to_bytes()[i]);
            }
            for i in 0..32 {
                assert_eq!(challenge_buffer[i + 16], payload.hmac[i]);
            }
        }
        let sig_data = BASE64_STANDARD.decode(&blob.sig).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&blob.ts.to_be_bytes());
        data.extend_from_slice(blob.cn.as_bytes());
        data.extend_from_slice(&challenge_buffer);

        let public_key =
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, bs.pkey.public_key().as_ref());
        public_key
            .verify(&data, &sig_data)
            .expect("signature verification failed");
    }

    #[tokio::test]
    async fn oauth_tls_accepts_trusted_auth_zpr_certificate() {
        let (tls_ca, cert, private_key) = test_tls_material(BAS_TLS_HOST);
        let (address, server) = start_test_auth_server(cert, private_key).await;
        let oauth = test_oauth(tls_ca);

        let nonce = oauth
            .preauthorize(address, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(nonce, [1u8; 32]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oauth_tls_rejects_untrusted_auth_zpr_certificate() {
        let (_server_ca, cert, private_key) = test_tls_material(BAS_TLS_HOST);
        let (address, server) = start_test_auth_server(cert, private_key).await;
        let (wrong_ca, _, _) = test_tls_material(BAS_TLS_HOST);
        let oauth = test_oauth(wrong_ca);

        assert!(
            oauth
                .preauthorize(address, "127.0.0.1".parse().unwrap())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oauth_tls_rejects_trusted_certificate_for_another_hostname() {
        let (tls_ca, cert, private_key) = test_tls_material("attacker.zpr");
        let (address, server) = start_test_auth_server(cert, private_key).await;
        let oauth = test_oauth(tls_ca);

        assert!(
            oauth
                .preauthorize(address, "127.0.0.1".parse().unwrap())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[test]
    fn auth_code_redirect_is_bound_to_the_expected_https_origin() {
        assert_eq!(
            parse_auth_code_location("https://auth.zpr/?code=abc_DEF-123").unwrap(),
            "abc_DEF-123"
        );
        for location in [
            "https://attacker.example/?code=abc",
            "http://auth.zpr/?code=abc",
            "https://auth.zpr.evil/?code=abc",
            "https://auth.zpr/?code=abc&state=other",
            "https://auth.zpr/?code=abc&code=def",
            "https://auth.zpr/?code=bad%20code",
        ] {
            assert!(parse_auth_code_location(location).is_err(), "{location}");
        }
    }
}
