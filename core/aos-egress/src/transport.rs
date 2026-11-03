//! The only outbound call in the core library. Adapters implement this;
//! everything else stops at an intent.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub channel: String,
    pub target: String,
    pub payload: Vec<u8>,
    pub payload_hash: String,
}

pub struct Outbound<'a> {
    pub channel: &'a str,
    pub target: &'a str,
    pub payload: &'a [u8],
    pub payload_hash: &'a str,
}

pub trait Transport {
    fn send(&mut self, req: &Outbound<'_>) -> Result<String, String>;
}

/// Test adapter. It records what the gate actually handed it.
#[derive(Default)]
pub struct RecordingTransport {
    pub sent: Vec<Recorded>,
    fail: Option<String>,
}

impl RecordingTransport {
    pub fn failing(message: impl Into<String>) -> Self {
        RecordingTransport { sent: Vec::new(), fail: Some(message.into()) }
    }
}

impl Transport for RecordingTransport {
    fn send(&mut self, req: &Outbound<'_>) -> Result<String, String> {
        if let Some(message) = &self.fail {
            return Err(message.clone());
        }
        self.sent.push(Recorded {
            channel: req.channel.to_owned(),
            target: req.target.to_owned(),
            payload: req.payload.to_vec(),
            payload_hash: req.payload_hash.to_owned(),
        });
        Ok("ok".into())
    }
}
