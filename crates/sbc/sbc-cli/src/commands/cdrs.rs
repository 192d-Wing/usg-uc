//! `sbc-cli cdrs` — Call Detail Records.
//!
//! `list`, `show` and `export` query the daemon's recent-CDR ring over the
//! gRPC `CdrService` (requires the `grpc` feature, like `trunk`). `verify`
//! checks CDR files offline: the SHA-384 hash chain and sequence of JSONL
//! files (in the order given), and the `.sha384` sidecar of rotated files.
//! It needs no daemon.
//!
//! A passing `verify` shows the files are self-consistent. The chain is
//! unkeyed, so it does not prove who wrote them: compare the sidecar
//! digests with the `CdrFileRotated` audit events (or the syslog copy).
//!
//! ## NIST 800-53 Rev5: AU-6 (Audit Review), AU-9 (tamper-evidence check),
//! SI-12 (CDRs carry PII; output goes only to stdout)

use std::path::Path;

use crate::args::{Args, CdrsCommand};
#[cfg(feature = "grpc")]
use crate::args::{CdrsFilter, OutputFormat};
use crate::commands::{CommandError, CommandResult};

pub fn run(args: &Args, cmd: CdrsCommand) -> CommandResult {
    match cmd {
        CdrsCommand::Verify { files } => verify(&files),
        other => run_query(args, other),
    }
}

/// Offline chain and sidecar verification. Fails (non-zero exit) on the
/// first file that does not verify.
fn verify(files: &[String]) -> CommandResult {
    if files.is_empty() {
        return Err(CommandError::new("usage: sbc-cli cdrs verify <FILE>..."));
    }
    let jsonl: Vec<&Path> = files
        .iter()
        .map(Path::new)
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    let reports = uc_cdr::verify_files(&jsonl)
        .map_err(|e| CommandError::new(format!("chain verification FAILED: {e}")))?;
    for (path, r) in jsonl.iter().zip(&reports) {
        println!(
            "OK  {}  node={} records={} sequence={}..{} chained={}",
            path.display(),
            r.node_id,
            r.records,
            r.first_sequence,
            r.last_sequence
                .map_or_else(|| "-".to_string(), |s| s.to_string()),
            r.chained
        );
    }
    for f in files {
        let path = Path::new(f);
        if !uc_cdr::chain::sidecar_path(path).exists() {
            if path.extension().is_some_and(|e| e == "csv") {
                println!("--  {f}  (CSV without a sidecar: open file, no digest yet)");
            }
            continue;
        }
        match uc_cdr::verify_sidecar(path) {
            Ok(true) => println!("OK  {f}  sha384 sidecar matches"),
            Ok(false) => {
                return Err(CommandError::new(format!(
                    "{f}: sha384 sidecar does NOT match"
                )));
            }
            Err(e) => return Err(CommandError::new(format!("{f}: {e}"))),
        }
    }
    // NIST-02: the chain is unkeyed; local verification alone is not an
    // integrity anchor.
    println!(
        "NOTE  chain and sidecars are tamper-evident only (unkeyed SHA-384). Anchor them by \
         comparing each sidecar with its CdrFileRotated audit event (chained, forwarded \
         uc-audit) or the syslog copy."
    );
    Ok(())
}

/// Parses `--since` (`90s`, `15m`, `1h`, `7d`) into milliseconds.
pub fn parse_since_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last()? {
        b's' => (s.get(..s.len() - 1)?, 1_000),
        b'm' => (s.get(..s.len() - 1)?, 60_000),
        b'h' => (s.get(..s.len() - 1)?, 3_600_000),
        b'd' => (s.get(..s.len() - 1)?, 86_400_000),
        _ => return None,
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

#[cfg(not(feature = "grpc"))]
fn run_query(args: &Args, cmd: CdrsCommand) -> CommandResult {
    let _ = (args, cmd);
    Err(CommandError::new(
        "cdrs list/show/export require the `grpc` feature; \
         rebuild with: cargo build --features grpc (cdrs verify works without it)",
    ))
}

#[cfg(feature = "grpc")]
fn run_query(args: &Args, cmd: CdrsCommand) -> CommandResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CommandError::new(format!("tokio init failed: {e}")))?
        .block_on(query_async(args, cmd))
}

#[cfg(feature = "grpc")]
fn list_request(f: &CdrsFilter) -> Result<sbc_grpc_api::sbc::ListCdrsRequest, CommandError> {
    let start_ms = match &f.since {
        Some(s) => {
            let back = parse_since_ms(s)
                .ok_or_else(|| CommandError::new(format!("invalid --since {s:?} (e.g. 1h)")))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            now.saturating_sub(back)
        }
        None => 0,
    };
    if let Some(d) = &f.disposition
        && uc_cdr::Disposition::parse(d).is_none()
    {
        return Err(CommandError::new(format!("unknown --disposition {d:?}")));
    }
    Ok(sbc_grpc_api::sbc::ListCdrsRequest {
        start_ms,
        caller: f.caller.clone().unwrap_or_default(),
        callee: f.callee.clone().unwrap_or_default(),
        disposition: f.disposition.clone().unwrap_or_default(),
        trunk: f.trunk.clone().unwrap_or_default(),
        page_size: 500,
        ..Default::default()
    })
}

/// Wraps a `CdrService` request with the local operator (`cli:$USER`), which
/// the daemon records in its `CdrExport` audit event (NIST 800-53 Rev5: AU-3).
#[cfg(feature = "grpc")]
fn as_cli_user<T>(msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    if let Ok(v) = format!("cli:{user}").parse() {
        req.metadata_mut().insert("x-sbc-user", v);
    }
    req
}

/// Pages through the ring until `limit` records (or the end).
#[cfg(feature = "grpc")]
async fn fetch(
    client: &mut sbc_grpc_api::sbc::cdr_service_client::CdrServiceClient<tonic::transport::Channel>,
    mut req: sbc_grpc_api::sbc::ListCdrsRequest,
    limit: usize,
) -> Result<Vec<uc_cdr::CallRecord>, CommandError> {
    let mut out = Vec::new();
    loop {
        let page = client
            .list_cdrs(as_cli_user(req.clone()))
            .await
            .map_err(|e| CommandError::new(format!("ListCdrs: {}", e.message())))?
            .into_inner();
        for p in &page.cdrs {
            out.push(sbc_grpc_api::cdr::from_proto(p).map_err(CommandError::new)?);
            if out.len() >= limit {
                return Ok(out);
            }
        }
        if page.next_page_token.is_empty() {
            return Ok(out);
        }
        req.page_token = page.next_page_token;
    }
}

/// Compact STIR/SHAKEN column: signed attestation `S:A`, inbound
/// verification `V:P`/`V:F`/`V:N` (passed/failed/none), `-` when neither.
#[cfg(feature = "grpc")]
fn stir_column(r: &uc_cdr::CallRecord) -> String {
    let mut s = String::new();
    if let Some(a) = r.stir_attestation {
        s.push_str("S:");
        s.push_str(a.as_str());
    }
    if let Some(v) = r.stir_verstat {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(match v {
            uc_cdr::Verstat::TnValidationPassed => "V:P",
            uc_cdr::Verstat::TnValidationFailed => "V:F",
            uc_cdr::Verstat::NoTnValidation => "V:N",
        });
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

#[cfg(feature = "grpc")]
async fn query_async(args: &Args, cmd: CdrsCommand) -> CommandResult {
    use sbc_grpc_api::sbc::GetCdrRequest;
    use sbc_grpc_api::sbc::cdr_service_client::CdrServiceClient;

    let mut client = CdrServiceClient::connect(args.grpc_url.clone())
        .await
        .map_err(|e| CommandError::new(format!("cannot connect to {}: {e}", args.grpc_url)))?;
    match cmd {
        CdrsCommand::List { filter } => {
            let recs = fetch(&mut client, list_request(&filter)?, filter.limit).await?;
            if args.format == OutputFormat::Json {
                let v = serde_json::to_string_pretty(&recs)
                    .map_err(|e| CommandError::new(e.to_string()))?;
                println!("{v}");
                return Ok(());
            }
            if recs.is_empty() {
                println!("No CDRs match.");
                return Ok(());
            }
            println!(
                "{:<20}  {:<13}  {:<16}  {:<16}  {:<14}  {:>4}  {:>9}  {:<8}  {:<6}",
                "RECORD",
                "SETUP(ms)",
                "CALLER",
                "CALLEE",
                "DISPOSITION",
                "SIP",
                "DUR(s)",
                "TRUNK",
                "STIR"
            );
            println!("{}", "-".repeat(120));
            for r in &recs {
                println!(
                    "{:<20}  {:<13}  {:<16.16}  {:<16.16}  {:<14}  {:>4}  {:>9}  {:<8}  {:<6}",
                    r.record_id,
                    r.setup_ms,
                    r.caller.escape_default().to_string(),
                    r.callee_dialed.escape_default().to_string(),
                    r.disposition.as_str(),
                    r.final_sip_status,
                    format!("{}.{}", r.duration_ms / 1000, (r.duration_ms % 1000) / 100),
                    r.final_trunk.as_deref().unwrap_or("-"),
                    stir_column(r),
                );
            }
        }
        CdrsCommand::Show { record_id } => {
            if record_id.is_empty() {
                return Err(CommandError::new("usage: sbc-cli cdrs show <RECORD_ID>"));
            }
            let p = client
                .get_cdr(as_cli_user(GetCdrRequest { record_id }))
                .await
                .map_err(|e| CommandError::new(format!("GetCdr: {}", e.message())))?
                .into_inner()
                .cdr
                .ok_or_else(|| CommandError::new("CDR not found"))?;
            let r = sbc_grpc_api::cdr::from_proto(&p).map_err(CommandError::new)?;
            let v =
                serde_json::to_string_pretty(&r).map_err(|e| CommandError::new(e.to_string()))?;
            println!("{v}");
        }
        CdrsCommand::Export { filter, format } => {
            let recs = fetch(&mut client, list_request(&filter)?, filter.limit).await?;
            let mut out = String::new();
            if format == "csv" {
                out.push_str(&uc_cdr::format::csv_header());
            }
            for r in &recs {
                let line = if format == "csv" {
                    uc_cdr::format::to_csv_row(r)
                } else {
                    uc_cdr::format::to_json_line(r)
                }
                .map_err(|e| CommandError::new(e.to_string()))?;
                out.push_str(&line);
                if !line.ends_with('\n') {
                    out.push('\n');
                }
            }
            print!("{out}");
        }
        CdrsCommand::Verify { files } => return verify(&files),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn since_parses() {
        assert_eq!(parse_since_ms("90s"), Some(90_000));
        assert_eq!(parse_since_ms("1h"), Some(3_600_000));
        assert_eq!(parse_since_ms("7d"), Some(604_800_000));
        assert_eq!(parse_since_ms("1"), None);
        assert_eq!(parse_since_ms("xh"), None);
        assert_eq!(parse_since_ms(""), None);
    }

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn write_cdrs(dir: &Path) -> TestResult<std::path::PathBuf> {
        let em = uc_cdr::CdrEmitter::start(
            uc_cdr::CdrEmitterConfig {
                node_id: "n1".into(),
                file: Some(uc_cdr::FileSinkConfig {
                    directory: dir.to_path_buf(),
                    rotate_interval: None,
                    fsync_interval: Duration::ZERO,
                    ..uc_cdr::FileSinkConfig::default()
                }),
                ..Default::default()
            },
            Vec::new(),
            None,
        )?;
        for i in 0..3 {
            assert!(em.emit(uc_cdr::CallRecord {
                caller: format!("100{i}"),
                ..Default::default()
            }));
        }
        assert!(em.shutdown(Duration::from_secs(5)));
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                return Ok(path);
            }
        }
        Err("no CDR file written".into())
    }

    #[test]
    fn verify_passes_then_fails_on_tamper() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = write_cdrs(dir.path())?;
        let f = file.display().to_string();
        assert!(verify(std::slice::from_ref(&f)).is_ok());
        let text = std::fs::read_to_string(&file)?;
        std::fs::write(&file, text.replacen("1001", "1009", 1))?;
        assert!(verify(&[f]).is_err());
        assert!(verify(&[]).is_err());
        Ok(())
    }
}
