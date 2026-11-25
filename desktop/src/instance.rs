//! Lightweight single-instance coordination over authenticated IPv4 loopback.
//!
//! When Wardr is minimized to the system tray / menu bar and the user launches
//! Wardr again from the Start menu, Applications, or desktop menu, the new
//! process signals the running instance to reveal and focus its window instead
//! of spawning a second dashboard backend.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct SingleInstanceGuard {
    marker_path: PathBuf,
    stop: Arc<AtomicBool>,
    port: u16,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port)),
            Duration::from_millis(150),
        );
        let _ = fs::remove_file(&self.marker_path);
    }
}

pub fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("Wardr");
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(profile).join("AppData").join("Local").join("Wardr");
        }
        std::env::temp_dir().join("Wardr")
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Wardr");
        }
        std::env::temp_dir().join("Wardr")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
            let path = PathBuf::from(state);
            if path.is_absolute() {
                return path.join("wardr");
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local").join("state").join("wardr");
        }
        std::env::temp_dir().join("wardr")
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    if !fill_os_random(&mut bytes) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let mut seed = nanos ^ (pid << 64) ^ 0x9e37_79b9_7f4a_7c15_u128;
        for chunk in bytes.chunks_mut(8) {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            chunk.copy_from_slice(&(seed as u64).to_le_bytes());
        }
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

#[cfg(unix)]
fn fill_os_random(buf: &mut [u8]) -> bool {
    use std::io::Read;
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .is_ok()
}

#[cfg(not(unix))]
fn fill_os_random(_buf: &mut [u8]) -> bool {
    false
}

fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, contents)?;
        let _ = fs::remove_file(path);
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn try_focus_existing(marker_path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(marker_path) else {
        return false;
    };
    let mut lines = contents.lines();
    let Some(port_str) = lines.next() else {
        return false;
    };
    let Some(token) = lines.next() else {
        return false;
    };
    let Ok(port) = port_str.trim().parse::<u16>() else {
        return false;
    };
    if port == 0 || token.len() < 32 {
        return false;
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(350)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    if writeln!(stream, "FOCUS {token}").is_err() {
        return false;
    }
    let mut reply = String::new();
    let mut reader = BufReader::new(stream);
    matches!(reader.read_line(&mut reply), Ok(n) if n > 0 && reply.trim() == "OK")
}

/// If another Wardr desktop window is already running, asks it to focus and
/// returns `None`. Otherwise starts the focus listener and returns a guard.
pub fn acquire_or_focus<F>(state_dir_override: Option<&Path>, on_focus: F) -> Option<SingleInstanceGuard>
where
    F: Fn() + Send + 'static,
{
    let base = state_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(app_data_dir);
    let marker_path = base.join(".wardr-desktop-instance");

    if try_focus_existing(&marker_path) {
        return None;
    }

    let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))) {
        Ok(l) => l,
        Err(_) => {
            // If loopback bind somehow fails, still allow the app to start.
            return Some(SingleInstanceGuard {
                marker_path,
                stop: Arc::new(AtomicBool::new(true)),
                port: 0,
            });
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let token = random_token();
    let _ = write_private_file(&marker_path, &format!("{port}\n{token}\n"));

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    thread::Builder::new()
        .name("wardr-instance".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = incoming else {
                    continue;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let mut line = String::new();
                let ok = {
                    let mut reader = BufReader::new(&stream);
                    reader.read_line(&mut line).is_ok()
                        && line.trim() == format!("FOCUS {token}")
                };
                if ok {
                    let _ = writeln!(stream, "OK");
                    on_focus();
                }
            }
        })
        .ok();

    Some(SingleInstanceGuard {
        marker_path,
        stop,
        port,
    })
}
