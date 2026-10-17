use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

const MAX_FRAME_LENGTH: usize = 8192;
const PUBLIC_KEY_MAX_LENGTH: usize = 1024;
const SHA256_LENGTH: usize = 32;
const RSA3072_SIGNATURE_LENGTH: usize = 384;

#[derive(Debug, Eq, PartialEq)]
struct ProtocolError;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Request {
    Public,
    Sign { digest: [u8; SHA256_LENGTH] },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Operation {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "sign")]
    Sign,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyBinding {
    reference: String,
    public_key_der: Vec<u8>,
    fingerprint: [u8; SHA256_LENGTH],
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Response {
    Public(KeyBinding),
    Signed {
        binding: KeyBinding,
        signature: Vec<u8>,
    },
    Unavailable(Operation),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRequestWire {
    version: u32,
    operation: PublicOperation,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum PublicOperation {
    Public,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequestWire {
    version: u32,
    operation: SignOperation,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum SignOperation {
    Sign,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RequestWire {
    Public(PublicRequestWire),
    Sign(SignRequestWire),
}

#[derive(Serialize)]
struct PublicRequestJson {
    version: u32,
    operation: &'static str,
}

#[derive(Serialize)]
struct SignRequestJson {
    version: u32,
    operation: &'static str,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicResponseWire {
    version: u32,
    operation: PublicOperation,
    reference: String,
    public_key: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignResponseWire {
    version: u32,
    operation: SignOperation,
    reference: String,
    public_key: String,
    fingerprint: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableResponseWire {
    version: u32,
    operation: Operation,
    error: UnavailableError,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum UnavailableError {
    Unavailable,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResponseWire {
    Public(PublicResponseWire),
    Signed(SignResponseWire),
    Unavailable(UnavailableResponseWire),
}

#[derive(Serialize)]
struct PublicResponseJson {
    version: u32,
    operation: &'static str,
    reference: String,
    public_key: String,
    fingerprint: String,
}

#[derive(Serialize)]
struct SignResponseJson {
    version: u32,
    operation: &'static str,
    reference: String,
    public_key: String,
    fingerprint: String,
    signature: String,
}

#[derive(Serialize)]
struct UnavailableResponseJson {
    version: u32,
    operation: &'static str,
    error: &'static str,
}

fn encode_frame(json: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if json.is_empty() || json.len() > MAX_FRAME_LENGTH {
        return Err(ProtocolError);
    }
    let length = u32::try_from(json.len()).map_err(|_| ProtocolError)?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(json);
    Ok(frame)
}

fn decode_frame(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    if frame.len() < 4 {
        return Err(ProtocolError);
    }
    let mut header = [0; 4];
    header.copy_from_slice(&frame[..4]);
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_LENGTH || frame.len() != length + 4 {
        return Err(ProtocolError);
    }
    Ok(&frame[4..])
}

fn encode_request(request: &Request) -> Result<Vec<u8>, ProtocolError> {
    let json = match request {
        Request::Public => serde_json::to_vec(&PublicRequestJson {
            version: 1,
            operation: "public",
        }),
        Request::Sign { digest } => serde_json::to_vec(&SignRequestJson {
            version: 1,
            operation: "sign",
            digest: STANDARD.encode(digest),
        }),
    }
    .map_err(|_| ProtocolError)?;
    encode_frame(&json)
}

fn decode_request(frame: &[u8]) -> Result<Request, ProtocolError> {
    let json = decode_frame(frame)?;
    let request: RequestWire = serde_json::from_slice(json).map_err(|_| ProtocolError)?;
    match request {
        RequestWire::Public(request) if request.version == 1 => match request.operation {
            PublicOperation::Public => Ok(Request::Public),
        },
        RequestWire::Sign(request) if request.version == 1 => match request.operation {
            SignOperation::Sign => {
                let digest = decode_base64(&request.digest, SHA256_LENGTH)?;
                let mut bytes = [0; SHA256_LENGTH];
                bytes.copy_from_slice(&digest);
                Ok(Request::Sign { digest: bytes })
            }
        },
        _ => Err(ProtocolError),
    }
}

fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    let json = match response {
        Response::Public(binding) => {
            validate_binding(binding)?;
            serde_json::to_vec(&PublicResponseJson {
                version: 1,
                operation: "public",
                reference: binding.reference.clone(),
                public_key: STANDARD.encode(&binding.public_key_der),
                fingerprint: encode_hex(&binding.fingerprint),
            })
        }
        Response::Signed { binding, signature } => {
            validate_binding(binding)?;
            if signature.len() != RSA3072_SIGNATURE_LENGTH {
                return Err(ProtocolError);
            }
            serde_json::to_vec(&SignResponseJson {
                version: 1,
                operation: "sign",
                reference: binding.reference.clone(),
                public_key: STANDARD.encode(&binding.public_key_der),
                fingerprint: encode_hex(&binding.fingerprint),
                signature: STANDARD.encode(signature),
            })
        }
        Response::Unavailable(operation) => {
            let operation = match operation {
                Operation::Public => "public",
                Operation::Sign => "sign",
            };
            serde_json::to_vec(&UnavailableResponseJson {
                version: 1,
                operation,
                error: "unavailable",
            })
        }
    }
    .map_err(|_| ProtocolError)?;
    encode_frame(&json)
}

fn decode_response(frame: &[u8]) -> Result<Response, ProtocolError> {
    let json = decode_frame(frame)?;
    let response: ResponseWire = serde_json::from_slice(json).map_err(|_| ProtocolError)?;
    match response {
        ResponseWire::Public(response) if response.version == 1 => match response.operation {
            PublicOperation::Public => Ok(Response::Public(decode_binding(
                response.reference,
                response.public_key,
                response.fingerprint,
            )?)),
        },
        ResponseWire::Signed(response) if response.version == 1 => match response.operation {
            SignOperation::Sign => {
                let binding = decode_binding(
                    response.reference,
                    response.public_key,
                    response.fingerprint,
                )?;
                let signature = decode_base64(&response.signature, RSA3072_SIGNATURE_LENGTH)?;
                Ok(Response::Signed { binding, signature })
            }
        },
        ResponseWire::Unavailable(response) if response.version == 1 => {
            let _ = response.error;
            Ok(Response::Unavailable(response.operation))
        }
        _ => Err(ProtocolError),
    }
}

fn decode_binding(
    reference: String,
    public_key: String,
    fingerprint: String,
) -> Result<KeyBinding, ProtocolError> {
    if !valid_reference(&reference) {
        return Err(ProtocolError);
    }
    let public_key_der = decode_base64_bounded(&public_key, PUBLIC_KEY_MAX_LENGTH)?;
    let fingerprint = decode_hex(&fingerprint)?;
    Ok(KeyBinding {
        reference,
        public_key_der,
        fingerprint,
    })
}

fn validate_binding(binding: &KeyBinding) -> Result<(), ProtocolError> {
    if !valid_reference(&binding.reference)
        || binding.public_key_der.is_empty()
        || binding.public_key_der.len() > PUBLIC_KEY_MAX_LENGTH
    {
        return Err(ProtocolError);
    }
    Ok(())
}

fn valid_reference(reference: &str) -> bool {
    !reference.is_empty() && reference.len() <= 1024 && !reference.chars().any(char::is_control)
}

fn decode_base64(text: &str, expected_length: usize) -> Result<Vec<u8>, ProtocolError> {
    let decoded = STANDARD.decode(text).map_err(|_| ProtocolError)?;
    if decoded.len() != expected_length || STANDARD.encode(&decoded) != text {
        return Err(ProtocolError);
    }
    Ok(decoded)
}

fn decode_base64_bounded(text: &str, maximum_length: usize) -> Result<Vec<u8>, ProtocolError> {
    let decoded = STANDARD.decode(text).map_err(|_| ProtocolError)?;
    if decoded.is_empty() || decoded.len() > maximum_length || STANDARD.encode(&decoded) != text {
        return Err(ProtocolError);
    }
    Ok(decoded)
}

fn encode_hex(bytes: &[u8; SHA256_LENGTH]) -> String {
    bytes.iter().fold(String::new(), |mut encoded, byte| {
        encoded.push_str(&format!("{byte:02x}"));
        encoded
    })
}

fn decode_hex(text: &str) -> Result<[u8; SHA256_LENGTH], ProtocolError> {
    if text.len() != SHA256_LENGTH * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError);
    }
    let mut fingerprint = [0; SHA256_LENGTH];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| ProtocolError)?;
    }
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::digest::{SHA256, digest};
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair, RsaKeyPair};

    struct FakeSigner {
        private_material_marker: &'static [u8],
        received_digests: Vec<[u8; SHA256_LENGTH]>,
    }

    impl FakeSigner {
        fn sign_digest(&mut self, digest: &[u8; SHA256_LENGTH]) -> Vec<u8> {
            self.received_digests.push(*digest);
            vec![0x5a; RSA3072_SIGNATURE_LENGTH]
        }
    }

    fn synthetic_binding() -> KeyBinding {
        let key = RsaKeyPair::generate(KeySize::Rsa3072).expect("synthetic test key generation");
        let public_key_der = key.public_key().as_ref().to_vec();
        let fingerprint = digest(&SHA256, &public_key_der);
        let mut fingerprint_bytes = [0; SHA256_LENGTH];
        fingerprint_bytes.copy_from_slice(fingerprint.as_ref());
        KeyBinding {
            reference: "endpoint/asset-42/runtime".into(),
            public_key_der,
            fingerprint: fingerprint_bytes,
        }
    }

    fn fake_helper_exchange(
        request_frame: &[u8],
        binding: &KeyBinding,
        signer: &mut FakeSigner,
    ) -> Result<Vec<u8>, ProtocolError> {
        match decode_request(request_frame)? {
            Request::Public => encode_response(&Response::Public(binding.clone())),
            Request::Sign { digest } => {
                let signature = signer.sign_digest(&digest);
                encode_response(&Response::Signed {
                    binding: binding.clone(),
                    signature,
                })
            }
        }
    }

    fn frame_json(json: &[u8]) -> Vec<u8> {
        encode_frame(json).expect("valid test frame")
    }

    #[test]
    fn public_request_and_response_match_v1_wire_shape() {
        let binding = synthetic_binding();
        let request = encode_request(&Request::Public).unwrap();
        assert_eq!(
            decode_frame(&request).unwrap(),
            br#"{"version":1,"operation":"public"}"#
        );

        let mut signer = FakeSigner {
            private_material_marker: b"synthetic-private-material",
            received_digests: Vec::new(),
        };
        let response = fake_helper_exchange(&request, &binding, &mut signer).unwrap();
        assert_eq!(
            decode_response(&response).unwrap(),
            Response::Public(binding)
        );
        assert!(signer.received_digests.is_empty());
        assert!(
            !request
                .windows(signer.private_material_marker.len())
                .any(|window| window == signer.private_material_marker)
        );
    }

    #[test]
    fn sign_request_passes_only_the_digest_and_binds_response_fields() {
        let binding = synthetic_binding();
        let digest = [0x31; SHA256_LENGTH];
        let request = encode_request(&Request::Sign { digest }).unwrap();
        let json = decode_frame(&request).unwrap();
        let encoded_digest = STANDARD.encode(digest);
        assert!(
            std::str::from_utf8(json)
                .unwrap()
                .contains(encoded_digest.as_str())
        );

        let mut signer = FakeSigner {
            private_material_marker: b"synthetic-private-material",
            received_digests: Vec::new(),
        };
        let response = fake_helper_exchange(&request, &binding, &mut signer).unwrap();
        assert_eq!(signer.received_digests, vec![digest]);
        assert!(
            !request
                .windows(signer.private_material_marker.len())
                .any(|window| window == signer.private_material_marker)
        );
        assert!(
            !response
                .windows(signer.private_material_marker.len())
                .any(|window| window == signer.private_material_marker)
        );
        assert_eq!(
            decode_response(&response).unwrap(),
            Response::Signed {
                binding,
                signature: vec![0x5a; RSA3072_SIGNATURE_LENGTH],
            }
        );
    }

    #[test]
    fn unavailable_response_matches_v1_shape() {
        let frame = encode_response(&Response::Unavailable(Operation::Sign)).unwrap();
        assert_eq!(
            decode_frame(&frame).unwrap(),
            br#"{"version":1,"operation":"sign","error":"unavailable"}"#
        );
        assert_eq!(
            decode_response(&frame).unwrap(),
            Response::Unavailable(Operation::Sign)
        );
    }

    #[test]
    fn request_decoder_rejects_malformed_operations_fields_and_digests() {
        for json in [
            br#"{"version":2,"operation":"public"}"#.as_slice(),
            br#"{"version":1,"operation":"unknown"}"#,
            br#"{"version":1,"operation":"public","digest":"AA=="}"#,
            br#"{"version":1,"operation":"sign"}"#,
            br#"{"version":1,"operation":"sign","digest":null}"#,
            br#"{"version":1,"operation":"sign","digest":"not-base64"}"#,
            br#"{"version":1,"operation":"public","operation":"sign"}"#,
            br#"{"version":1,"operation":"public","extra":true}"#,
        ] {
            assert!(
                decode_request(&frame_json(json)).is_err(),
                "accepted {json:?}"
            );
        }
        let short_digest = format!(
            r#"{{"version":1,"operation":"sign","digest":"{}"}}"#,
            STANDARD.encode([0u8; SHA256_LENGTH - 1])
        );
        assert!(decode_request(&frame_json(short_digest.as_bytes())).is_err());
    }

    #[test]
    fn response_decoder_rejects_malformed_fields_and_lengths() {
        for json in [
            br#"{"version":2,"operation":"public","reference":"r","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}"#.as_slice(),
            br#"{"version":1,"operation":"other","reference":"r","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}"#.as_slice(),
            br#"{"version":1,"operation":"public","reference":"r","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","signature":""}"#,
            br#"{"version":1,"operation":"public","reference":"r","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","extra":1}"#,
            br#"{"version":1,"operation":"public","reference":"r","reference":"other","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            br#"{"version":1,"operation":"public","reference":"r","public_key":"AQ==","fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            br#"{"version":1,"operation":"sign","reference":"r","public_key":"AQ==","fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","signature":"AA=="}"#,
            br#"{"version":1,"operation":"sign","error":"other"}"#,
        ] {
            assert!(
                decode_response(&frame_json(json)).is_err(),
                "accepted {json:?}"
            );
        }
    }

    #[test]
    fn frame_decoder_rejects_bad_lengths_and_trailing_bytes() {
        for frame in [
            vec![],
            vec![0, 0, 0],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 1, b'{', 0],
            vec![0, 0, 0x20, 0x01],
        ] {
            assert!(decode_frame(&frame).is_err(), "accepted {frame:?}");
        }
    }

    #[test]
    fn response_encoder_rejects_invalid_binding_and_signature_lengths() {
        let mut binding = synthetic_binding();
        binding.reference = "bad\nreference".into();
        assert!(encode_response(&Response::Public(binding.clone())).is_err());
        binding.reference = "valid-reference".into();
        binding.public_key_der.clear();
        assert!(encode_response(&Response::Public(binding.clone())).is_err());
        binding = synthetic_binding();
        assert!(
            encode_response(&Response::Signed {
                binding,
                signature: vec![0; RSA3072_SIGNATURE_LENGTH - 1],
            })
            .is_err()
        );
    }
}
