//! Software key on disk, CLI approval (SPEC §12.7). Refuses to run unless
//! this crate was built with debug assertions.

use std::path::Path;

use aos_types::cbor::{self, Value};
use aos_types::codec::{self, record};
use aos_types::ulid::Entropy;
use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::Error;
use crate::request::{approval_message, cbor_bytes, sign_bytes, signing_key, trust_id, verify_bytes};

pub const DEV_BANNER: &str = "不安全：开发确认器";

const MAGIC: &[u8] = b"AOSDEV01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub decision: String,
    pub signature: Vec<u8>,
}

pub struct DevConfirmer {
    signing: SigningKey,
}

impl DevConfirmer {
    pub fn available() -> bool {
        cfg!(debug_assertions)
    }

    pub fn ephemeral(entropy: &mut dyn Entropy) -> Result<Self, Error> {
        let key = signing_key(entropy);
        Self::from_secret(&key.to_bytes())
    }

    pub fn generate(path: &Path, entropy: &mut dyn Entropy) -> Result<Self, Error> {
        let confirmer = Self::ephemeral(entropy)?;
        let mut bytes = Vec::with_capacity(MAGIC.len() + 32);
        bytes.extend(MAGIC);
        bytes.extend(confirmer.signing.to_bytes().into_iter());
        std::fs::write(path, bytes).map_err(|e| Error::Io(e.to_string()))?;
        Ok(confirmer)
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(|e| Error::Io(e.to_string()))?;
        let secret = bytes.strip_prefix(MAGIC).ok_or_else(|| Error::Bad("not a dev confirmer key".into()))?;
        Self::from_secret(secret)
    }

    fn from_secret(secret: &[u8]) -> Result<Self, Error> {
        if !Self::available() {
            return Err(Error::DebugOnly);
        }
        let signing = SigningKey::from_slice(secret).map_err(|_| Error::BadKey)?;
        Ok(DevConfirmer { signing })
    }

    pub fn key_id(&self) -> String {
        trust_id(&self.verifying())
    }

    pub fn verifying(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing)
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn approve(&self, request_bytes: &[u8], decision: &str) -> Result<Approval, Error> {
        if !matches!(decision, "approve" | "deny") {
            return Err(Error::Decision);
        }
        let signature = sign_bytes(&self.signing, &approval_message(request_bytes, decision));
        Ok(Approval { decision: decision.to_owned(), signature })
    }
}

impl Approval {
    pub fn verify(&self, key: &VerifyingKey, request_bytes: &[u8]) -> Result<(), Error> {
        if !matches!(self.decision.as_str(), "approve" | "deny") {
            return Err(Error::Decision);
        }
        verify_bytes(key, &approval_message(request_bytes, &self.decision), &self.signature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&record([
            ("decision", Value::from(self.decision.as_str())),
            ("signature", Value::Bytes(self.signature.clone())),
        ]))
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        let value = cbor::decode(input).map_err(|e| Error::Bad(e.to_string()))?;
        let mut r = codec::Record::new(&value).map_err(|e| Error::Bad(e.to_string()))?;
        let approval = Approval {
            decision: r.req("decision", codec::text).map_err(|e| Error::Bad(e.to_string()))?.to_owned(),
            signature: r.req("signature", cbor_bytes).map_err(|e| Error::Bad(e.to_string()))?.to_vec(),
        };
        r.finish().map_err(|e| Error::Bad(e.to_string()))?;
        if !matches!(approval.decision.as_str(), "approve" | "deny") {
            return Err(Error::Decision);
        }
        Ok(approval)
    }
}
