//! Basic network troubleshooting: ping, traceroute, port check, DNS lookup.
//!
//! Deliberately "nothing fancy": ping and traceroute shell out to the Windows
//! built-ins rather than crafting raw ICMP, because raw sockets need elevation
//! and re-implementing ping badly helps nobody. Output streams line-by-line to
//! the frontend over an event channel — a traceroute can take two minutes, and
//! a spinner with no output for two minutes reads as a hang.
//!
//! Every spawned console child gets CREATE_NO_WINDOW: the app is built with
//! `windows_subsystem = "windows"`, and without the flag each ping would flash
//! a black console window on screen.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// One line of tool output, or the final result marker.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolEvent {
    pub run_id: String,
    pub line: String,
    pub done: bool,
}

/// Active runs, so a long traceroute can be cancelled.
#[derive(Default)]
pub struct NetTools {
    runs: DashMap<String, tokio::task::JoinHandle<()>>,
}

/// Targets reach a command line, so the character set is fenced hard even
/// though nothing goes through a shell: hostnames, IPv4/IPv6, nothing else.
fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() || target.len() > 253 {
        return Err("invalid target".into());
    }
    // A leading '-' would be parsed by ping/traceroute as an OPTION, not a
    // host (argv, so not shell injection — but e.g. a flood/-flag or an output
    // option is still unwanted). Reject it outright.
    if target.starts_with('-') {
        return Err(format!("invalid target (cannot start with '-'): {target}"));
    }
    if !target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
    {
        return Err(format!("target contains invalid characters: {target}"));
    }
    Ok(())
}

/// Decode one raw output line. Lossy on purpose: localized Windows ping and
/// tracert write the OEM code page (CP850 "ausgeführt", CP866, GBK...), which
/// is not UTF-8. A strict decode fails the whole stream at the first accented
/// byte; a lossy one shows a replacement char and keeps every reply line.
fn decode_line(raw: &[u8]) -> String {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Stream a child pipe to the frontend line by line until EOF. A read error
/// is treated as end of stream; bad encoding is not an error (see above).
async fn emit_lines<R: AsyncRead + Unpin>(pipe: R, app: &AppHandle, rid: &str) {
    let mut reader = BufReader::new(pipe);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let _ = app.emit(
                    &format!("net://{rid}"),
                    ToolEvent { run_id: rid.to_string(), line: decode_line(&buf), done: false },
                );
            }
        }
    }
}

impl NetTools {
    /// Start ping or traceroute, streaming output on `net://{run_id}`.
    pub fn start_process_tool(
        &self,
        app: AppHandle,
        run_id: String,
        tool: &str,
        target: &str,
    ) -> Result<(), String> {
        validate_target(target)?;

        // The built-ins differ per OS in both name and flags. All variants stay
        // finite (a fixed count / hop cap) so a run can never hang the UI.
        let (program, args): (&str, Vec<String>) = match tool {
            "ping" => {
                // -n/-c 4: four echoes. Windows -w is ms; Linux -W is seconds;
                // macOS ping has no portable per-reply timeout flag, so rely on
                // the fixed count there.
                #[cfg(target_os = "windows")]
                {
                    ("ping", vec!["-n".into(), "4".into(), "-w".into(), "1500".into(), target.into()])
                }
                #[cfg(target_os = "macos")]
                {
                    ("ping", vec!["-c".into(), "4".into(), target.into()])
                }
                #[cfg(all(unix, not(target_os = "macos")))]
                {
                    ("ping", vec!["-c".into(), "4".into(), "-W".into(), "2".into(), target.into()])
                }
            }
            "traceroute" => {
                // No reverse DNS per hop (the usual slowness); cap at 20 hops.
                #[cfg(target_os = "windows")]
                {
                    ("tracert", vec!["-d".into(), "-h".into(), "20".into(), "-w".into(), "1000".into(), target.into()])
                }
                #[cfg(not(target_os = "windows"))]
                {
                    ("traceroute", vec!["-n".into(), "-m".into(), "20".into(), "-w".into(), "1".into(), target.into()])
                }
            }
            other => return Err(format!("unknown tool: {other}")),
        };

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
        // kill_on_drop is what actually terminates the child on cancel: aborting
        // the task below drops this `child`, and without this flag tokio leaves
        // the ping/traceroute running as an orphan. With it, the OS process is
        // killed and reaped when the task is aborted.
        cmd.kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

        let mut child = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;

        let rid = run_id.clone();
        let task = tokio::spawn(async move {
            // Stream stderr in parallel so a failure's message ("unknown host",
            // "operation not permitted") reaches the user instead of being
            // silently swallowed. When the child ends or is killed its stderr
            // pipe closes, ending this reader.
            let err_app = app.clone();
            let err_rid = rid.clone();
            let err_reader = tokio::spawn(async move {
                emit_lines(stderr, &err_app, &err_rid).await;
            });

            emit_lines(stdout, &app, &rid).await;
            let _ = err_reader.await;

            // Report a non-zero or failed exit rather than concealing it behind
            // a clean "done": a traceroute that could not resolve its target
            // should not look identical to a successful one.
            let status = child.wait().await;
            let final_line = match status {
                Ok(s) if s.success() => String::new(),
                Ok(s) => format!("[process exited with {s}]"),
                Err(e) => format!("[could not wait for process: {e}]"),
            };
            let _ = app.emit(
                &format!("net://{rid}"),
                ToolEvent { run_id: rid.clone(), line: final_line, done: true },
            );
        });
        // Runs that ended on their own are never cancelled, so nothing else
        // removes them: prune finished handles here to keep the map bounded.
        // A replaced handle for the same id is aborted, not silently dropped,
        // so its child cannot outlive the ability to cancel it.
        self.runs.retain(|_, h| !h.is_finished());
        if let Some(old) = self.runs.insert(run_id, task) {
            old.abort();
        }
        Ok(())
    }

    /// TCP port check. Three answers, and the distinction matters in network
    /// debugging: open (connected), closed (actively refused — the host is
    /// there, the service is not), filtered (timeout — a firewall is eating
    /// the SYN, or the host is gone).
    pub async fn port_check(target: &str, port: u16, timeout_ms: u64) -> Result<String, String> {
        validate_target(target)?;
        let started = Instant::now();
        match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect((target, port)),
        )
        .await
        {
            Ok(Ok(_)) => Ok(format!(
                "{target}:{port} OPEN ({} ms)",
                started.elapsed().as_millis()
            )),
            Ok(Err(e)) => Ok(format!(
                "{target}:{port} CLOSED — connection refused ({e}). The host answered; nothing is listening on that port."
            )),
            Err(_) => Ok(format!(
                "{target}:{port} FILTERED — no reply in {timeout_ms} ms. A firewall is dropping it, or the host is unreachable."
            )),
        }
    }

    /// DNS resolution via the OS resolver — the same answer every other app on
    /// this machine would get, which is exactly what is being debugged.
    pub async fn dns_lookup(target: &str) -> Result<Vec<String>, String> {
        validate_target(target)?;
        let addrs = tokio::net::lookup_host((target, 0))
            .await
            .map_err(|e| format!("{target}: {e}"))?;
        let mut out: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
        out.dedup();
        if out.is_empty() {
            return Err(format!("{target}: no addresses returned"));
        }
        Ok(out)
    }

    pub fn cancel(&self, run_id: &str) {
        if let Some((_, task)) = self.runs.remove(run_id) {
            task.abort();
        }
    }
}

/* -------------------------------------------------------------------------- */

/// One host's reachability probe result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub id: String,
    pub reachable: bool,
    /// Connect time in ms when reachable.
    pub ms: Option<u64>,
}

/// Probe many hosts' SSH ports concurrently.
///
/// TCP connect to the configured port, not ICMP: the question an SSH client
/// answers is "can I connect", and plenty of gear that drops ping still
/// accepts 22. Concurrency is bounded so probing a 200-host catalogue does
/// not open 200 sockets at once through a stateful firewall.
pub async fn probe_hosts(targets: Vec<(String, String, u16)>) -> Vec<ProbeResult> {
    let sem = Arc::new(tokio::sync::Semaphore::new(16));
    let mut set = tokio::task::JoinSet::new();

    for (id, host, port) in targets {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await;
            let started = Instant::now();
            let ok = tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            ProbeResult {
                id,
                reachable: ok,
                ms: ok.then(|| started.elapsed().as_millis() as u64),
            }
        });
    }

    let mut out = Vec::new();
    while let Some(Ok(r)) = set.join_next().await {
        out.push(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::decode_line;

    #[test]
    fn decode_line_strips_crlf_and_keeps_utf8() {
        assert_eq!(decode_line(b"Reply from 1.1.1.1\r\n"), "Reply from 1.1.1.1");
        assert_eq!(decode_line(b"no newline"), "no newline");
        assert_eq!(decode_line(b"\r\n"), "");
        assert_eq!(decode_line("Обмен пакетами\n".as_bytes()), "Обмен пакетами");
    }

    #[test]
    fn decode_line_survives_oem_code_page_bytes() {
        // CP850 "Ping wird ausgeführt für" (ü = 0x81): invalid UTF-8, which a
        // strict line reader turns into an error that ends the stream.
        let raw = b"Ping wird ausgef\x81hrt f\x81r 1.1.1.1\r\n";
        let line = decode_line(raw);
        assert!(line.starts_with("Ping wird ausgef"));
        assert!(line.ends_with("r 1.1.1.1"));
        assert!(line.contains('\u{FFFD}'));
    }
}
