//! Private Python runtime preparation and supervised Wardr backend lifecycle.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const DESKTOP_RESTART_EXIT_CODE: i32 = 75;
const LAUNCH_PREFIX: &str = "Wardr is running at ";
const DESKTOP_EVENT_FOCUS: &str = "WARDR_DESKTOP_EVENT focus";

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub python_override: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub offline: bool,
    pub interval: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum BackendEvent {
    Status { headline: String, detail: String },
    Ready { origin: String, launch_url: String },
    FocusWindow,
    Restarting,
    Failed(String),
}

struct RunningChild {
    #[cfg(unix)]
    pid: u32,
    child: Child,
    _stdin: Option<ChildStdin>,
}

pub struct BackendSupervisor {
    shutting_down: Arc<AtomicBool>,
    active: Arc<Mutex<Option<RunningChild>>>,
}

impl BackendSupervisor {
    pub fn start<F>(config: BackendConfig, emit: F) -> Self
    where
        F: Fn(BackendEvent) + Send + Sync + 'static,
    {
        let shutting_down = Arc::new(AtomicBool::new(false));
        let active: Arc<Mutex<Option<RunningChild>>> = Arc::new(Mutex::new(None));

        let stop_flag = Arc::clone(&shutting_down);
        let active_slot = Arc::clone(&active);
        let emit = Arc::new(emit);

        thread::Builder::new()
            .name("wardr-backend".into())
            .spawn(move || {
                supervisor_loop(config, stop_flag, active_slot, emit);
            })
            .expect("failed to spawn Wardr backend supervisor thread");

        Self {
            shutting_down,
            active,
        }
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let taken = self.active.lock().ok().and_then(|mut guard| guard.take());
        if let Some(mut running) = taken {
            // Closing stdin notifies wardr's desktop watcher thread to shut down gracefully
            // on Windows, macOS, and Linux alike.
            drop(running._stdin.take());
            #[cfg(unix)]
            {
                // Also send SIGTERM on POSIX for immediate graceful shutdown.
                unsafe {
                    libc::kill(running.pid as libc::pid_t, libc::SIGTERM);
                }
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match running.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => thread::sleep(Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            let _ = running.child.kill();
            let _ = running.child.wait();
        }
    }
}

impl Drop for BackendSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn configure_hidden(cmd: &mut Command) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = cmd;
    }
}

pub fn bundle_payload_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let contents = exe.parent()?.parent()?;
    let payload = contents.join("Resources").join("payload");
    if payload.join("install.py").is_file() {
        Some(payload)
    } else {
        None
    }
}

pub fn macos_runtime_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME environment variable is not set.".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Wardr Runtime"))
}

pub fn prepare_payload(payload: &Path, location: &Path) -> Result<(), String> {
    let python = if cfg!(target_os = "windows") {
        payload.join("python").join("python.exe")
    } else {
        payload.join("python").join("bin").join("python3")
    };
    let installer = payload.join("install.py");
    if !python.is_file() || !installer.is_file() {
        return Err(format!(
            "The Wardr installer payload is incomplete at {}.",
            payload.display()
        ));
    }

    let mut cmd = Command::new(&python);
    configure_hidden(&mut cmd);
    cmd.arg("-I")
        .arg(&installer)
        .arg("--install-dir")
        .arg(location)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .output()
        .map_err(|err| format!("Could not start Wardr setup: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = String::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        message.push_str(stderr.trim());
    }
    if !stdout.trim().is_empty() {
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(stdout.trim());
    }
    if message.is_empty() {
        message = format!(
            "Wardr setup exited with status {}.",
            output.status.code().unwrap_or(1)
        );
    }
    Err(message)
}

fn resolve_python<F>(config: &BackendConfig, emit: &F) -> Result<PathBuf, String>
where
    F: Fn(BackendEvent),
{
    if let Some(ref custom) = config.python_override {
        if custom.is_file() {
            return Ok(custom.clone());
        }
        return Err(format!(
            "Configured Python interpreter was not found at {}.",
            custom.display()
        ));
    }

    if let Some(env_py) = std::env::var_os("WARDR_DESKTOP_PYTHON") {
        let candidate = PathBuf::from(env_py);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    // macOS .app bundle: provision private runtime into ~/Library/Application Support/Wardr Runtime
    if let Some(payload) = bundle_payload_dir() {
        let location = macos_runtime_dir()?;
        let venv_python = location.join("venv").join("bin").join("python3");
        if !venv_python.is_file() {
            emit(BackendEvent::Status {
                headline: "Preparing Wardr…".into(),
                detail: "Setting up your private Wardr runtime for first launch.".into(),
            });
        }
        prepare_payload(&payload, &location)?;
        if venv_python.is_file() {
            return Ok(venv_python);
        }
        return Err(format!(
            "Wardr prepared its runtime, but {} is missing.",
            venv_python.display()
        ));
    }

    // Installed Windows / Linux layout: venv next to the native desktop binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidates = if cfg!(target_os = "windows") {
                vec![dir.join("venv").join("Scripts").join("python.exe")]
            } else {
                vec![
                    dir.join("venv").join("bin").join("python3"),
                    dir.join("venv").join("bin").join("python"),
                ]
            };
            for candidate in candidates {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    // Local development fallback from repo root or desktop/
    if let Ok(cwd) = std::env::current_dir() {
        let roots = [cwd.clone(), cwd.parent().map(Path::to_path_buf).unwrap_or(cwd)];
        for root in roots {
            let candidates = if cfg!(target_os = "windows") {
                vec![root.join(".venv").join("Scripts").join("python.exe")]
            } else {
                vec![
                    root.join(".venv").join("bin").join("python"),
                    root.join(".venv").join("bin").join("python3"),
                ]
            };
            for candidate in candidates {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err("Could not locate the installed Wardr Python runtime. Reinstall Wardr and try again.".into())
}

pub fn parse_launch_line(line: &str) -> Option<(String, String)> {
    let url = line.trim().strip_prefix(LAUNCH_PREFIX)?.trim();
    if !url.starts_with("http://127.0.0.1:") {
        return None;
    }
    let after_scheme = &url["http://".len()..];
    let slash_idx = after_scheme.find('/')?;
    let host_port = &after_scheme[..slash_idx];
    let port_str = host_port.strip_prefix("127.0.0.1:")?;
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    let rest = &after_scheme[slash_idx..];
    if !rest.starts_with("/#access=") || rest.len() <= "/#access=".len() {
        return None;
    }
    Some((format!("http://{host_port}"), url.to_string()))
}

fn supervisor_loop<F>(
    config: BackendConfig,
    shutting_down: Arc<AtomicBool>,
    active: Arc<Mutex<Option<RunningChild>>>,
    emit: Arc<F>,
) where
    F: Fn(BackendEvent) + Send + Sync + 'static,
{
    let python = match resolve_python(&config, emit.as_ref()) {
        Ok(path) => path,
        Err(message) => {
            emit(BackendEvent::Failed(message));
            return;
        }
    };

    loop {
        if shutting_down.load(Ordering::SeqCst) {
            return;
        }

        let mut cmd = Command::new(&python);
        configure_hidden(&mut cmd);
        cmd.arg("-I").arg("-u").arg("-m").arg("wardr");
        if let Some(ref state_dir) = config.state_dir {
            cmd.arg("--state-dir").arg(state_dir);
        }
        cmd.arg("serve").arg("--port").arg("0").arg("--no-browser");
        if config.offline {
            cmd.arg("--offline");
        }
        if let Some(interval) = config.interval {
            cmd.arg("--interval").arg(interval.to_string());
        }
        cmd.env("WARDR_DESKTOP_SHELL", "1")
            .env("PYTHONUNBUFFERED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                emit(BackendEvent::Failed(format!(
                    "Wardr could not start its local security engine ({err})."
                )));
                return;
            }
        };

        #[cfg(unix)]
        let pid = child.id();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        if let Ok(mut guard) = active.lock() {
            *guard = Some(RunningChild {
                #[cfg(unix)]
                pid,
                child,
                _stdin: stdin,
            });
        }

        // Drain stderr concurrently so the child never blocks and errors are captured.
        let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let stderr_collector = Arc::clone(&stderr_lines);
        let stderr_thread = stderr.map(|pipe| {
            thread::Builder::new()
                .name("wardr-stderr".into())
                .spawn(move || {
                    let reader = BufReader::new(pipe);
                    for line in reader.lines().map_while(Result::ok) {
                        if let Ok(mut buf) = stderr_collector.lock() {
                            if buf.len() >= 40 {
                                buf.remove(0);
                            }
                            buf.push(line);
                        }
                    }
                })
                .ok()
        });

        let mut announced = false;
        if let Some(pipe) = stdout {
            let reader = BufReader::new(pipe);
            for line in reader.lines().map_while(Result::ok) {
                if !announced {
                    if let Some((origin, launch_url)) = parse_launch_line(&line) {
                        announced = true;
                        emit(BackendEvent::Ready { origin, launch_url });
                        continue;
                    }
                }
                if line.trim() == DESKTOP_EVENT_FOCUS {
                    emit(BackendEvent::FocusWindow);
                }
            }
        }

        if let Some(Some(handle)) = stderr_thread {
            let _ = handle.join();
        }

        // Wait for the child to finish and inspect its exit code.
        let status = {
            let taken = active.lock().ok().and_then(|mut guard| guard.take());
            taken.and_then(|mut running| running.child.wait().ok())
        };

        if shutting_down.load(Ordering::SeqCst) {
            return;
        }

        match status.and_then(|s| s.code()) {
            Some(DESKTOP_RESTART_EXIT_CODE) => {
                emit(BackendEvent::Restarting);
                thread::sleep(Duration::from_millis(150));
                continue;
            }
            Some(0) => {
                // Clean exit when not restarting (e.g., external termination).
                return;
            }
            other => {
                let diag = stderr_lines
                    .lock()
                    .ok()
                    .map(|lines| lines.join("\n"))
                    .unwrap_or_default();
                let message = if !diag.trim().is_empty() {
                    diag
                } else {
                    format!(
                        "Wardr's local engine stopped unexpectedly (exit code {}).",
                        other
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    )
                };
                emit(BackendEvent::Failed(message));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_loopback_launch_url() {
        let line = "Wardr is running at http://127.0.0.1:56507/#access=C99U9rL2zlh54oU3X4xWC9IS6rHJ3B6JVCj1xTdNJfM";
        let parsed = parse_launch_line(line).expect("should parse valid launch URL");
        assert_eq!(parsed.0, "http://127.0.0.1:56507");
        assert_eq!(
            parsed.1,
            "http://127.0.0.1:56507/#access=C99U9rL2zlh54oU3X4xWC9IS6rHJ3B6JVCj1xTdNJfM"
        );
    }

    #[test]
    fn rejects_non_loopback_or_malformed_urls() {
        assert!(parse_launch_line("Wardr is running at https://example.com/#access=abc").is_none());
        assert!(parse_launch_line("Wardr is running at http://127.0.0.1:0/#access=abc").is_none());
        assert!(parse_launch_line("Wardr is running at http://127.0.0.1:8080/").is_none());
        assert!(parse_launch_line("Some random log line").is_none());
    }
}
