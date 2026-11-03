//! `aos-dev-confirm keygen <path>`
//! `aos-dev-confirm approve <key> <request> <approve|deny> <out>`

use std::path::Path;

use aos_confirm::{AGENT_SUMMARY_MARK, Approval, ApprovalRequest, DEV_BANNER, DevConfirmer};
use aos_types::ulid::Entropy;

struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        let mut file = std::fs::File::open("/dev/urandom").expect("urandom");
        std::io::Read::read_exact(&mut file, buf).expect("urandom");
    }
}

fn main() {
    if !DevConfirmer::available() {
        eprintln!("{DEV_BANNER}");
        eprintln!("开发确认器只能在 debug 构建里启用");
        std::process::exit(1);
    }
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "keygen" => keygen(args.next()),
        "approve" => approve(args.next(), args.next(), args.next(), args.next()),
        _ => Err("usage: aos-dev-confirm keygen <path> | approve <key> <request> <approve|deny> <out>".into()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

fn keygen(path: Option<String>) -> Result<(), String> {
    let path = path.ok_or("missing key path")?;
    let confirmer = DevConfirmer::generate(Path::new(&path), &mut OsEntropy).map_err(|e| e.to_string())?;
    println!("{DEV_BANNER}");
    println!("{}", confirmer.key_id());
    Ok(())
}

fn approve(
    key: Option<String>,
    request: Option<String>,
    decision: Option<String>,
    out: Option<String>,
) -> Result<(), String> {
    let key = key.ok_or("missing key path")?;
    let request = request.ok_or("missing request path")?;
    let decision = decision.ok_or("missing decision")?;
    let out = out.ok_or("missing output path")?;
    let confirmer = DevConfirmer::load(Path::new(&key)).map_err(|e| e.to_string())?;
    let bytes = std::fs::read(&request).map_err(|e| e.to_string())?;
    let parsed = ApprovalRequest::from_envelope(&bytes).map_err(|e| e.to_string())?;
    println!("{DEV_BANNER}");
    for line in &parsed.summary {
        println!("{}: {}", line.label, line.value);
    }
    for item in &parsed.items {
        if let Some(text) = &item.agent_summary {
            println!("{AGENT_SUMMARY_MARK}: {text}");
        }
    }
    let approval = confirmer.approve(&parsed.canonical_bytes(), &decision).map_err(|e| e.to_string())?;
    std::fs::write(&out, approval.to_bytes()).map_err(|e| e.to_string())?;
    let _ = Approval::from_bytes(&approval.to_bytes());
    Ok(())
}
