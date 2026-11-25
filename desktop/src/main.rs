#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod backend;
mod instance;
mod splash;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use backend::{BackendConfig, BackendEvent, BackendSupervisor};
use image::imageops::FilterType;
use muda::MenuEvent;
#[cfg(target_os = "macos")]
use muda::accelerator::{Accelerator, Code, Modifiers};
use muda::{Menu, MenuItem, PredefinedMenuItem};
#[cfg(target_os = "macos")]
use muda::Submenu;
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tray_icon::{Icon as TrayIconImage, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use wry::{NewWindowResponse, WebContext, WebView, WebViewBuilder};

const ICON_PNG: &[u8] = include_bytes!("../../wardr/static/wardr-mark.png");

const MENU_ID_OPEN: &str = "wardr.open";
const MENU_ID_QUIT: &str = "wardr.quit";
#[cfg(target_os = "macos")]
const MENU_ID_BACK: &str = "wardr.back";
#[cfg(target_os = "macos")]
const MENU_ID_FORWARD: &str = "wardr.forward";
#[cfg(target_os = "macos")]
const MENU_ID_RELOAD: &str = "wardr.reload";
#[cfg(target_os = "macos")]
const MENU_ID_CLOSE_WIN: &str = "wardr.close_window";

#[derive(Debug)]
enum UserEvent {
    Backend(BackendEvent),
    FocusWindow,
    MenuAction(String),
    TrayClick,
}

struct CliArgs {
    prepare_only: Option<PathBuf>,
    backend: BackendConfig,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = std::env::args().skip(1);
    let mut prepare_only = None;
    let mut python_override = None;
    let mut state_dir = None;
    let mut offline = false;
    let mut interval = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--prepare-only" => {
                let target = args
                    .next()
                    .ok_or_else(|| "Expected a destination path after --prepare-only.".to_string())?;
                prepare_only = Some(PathBuf::from(target));
            }
            "--python" => {
                let target = args
                    .next()
                    .ok_or_else(|| "Expected a Python path after --python.".to_string())?;
                python_override = Some(PathBuf::from(target));
            }
            "--state-dir" => {
                let target = args
                    .next()
                    .ok_or_else(|| "Expected a directory after --state-dir.".to_string())?;
                state_dir = Some(PathBuf::from(target));
            }
            "--offline" => {
                offline = true;
            }
            "--interval" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "Expected an integer after --interval.".to_string())?;
                let secs: u32 = raw
                    .parse()
                    .map_err(|_| "Expected an integer number of seconds for --interval.".to_string())?;
                interval = Some(secs);
            }
            // Ignore macOS Process Serial Number argument when launched by LaunchServices
            other if other.starts_with("-psn_") => {}
            other => {
                return Err(format!("Unrecognized option: {other}"));
            }
        }
    }

    Ok(CliArgs {
        prepare_only,
        backend: BackendConfig {
            python_override,
            state_dir,
            offline,
            interval,
        },
    })
}

fn load_icons() -> (Option<WindowIcon>, Option<TrayIconImage>) {
    let Ok(img) = image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png) else {
        return (None, None);
    };
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let window_icon = WindowIcon::from_rgba(rgba.into_raw(), w, h).ok();

    let tray_size = if cfg!(target_os = "macos") { 36 } else { 32 };
    let tray_rgba = img
        .resize_exact(tray_size, tray_size, FilterType::Lanczos3)
        .to_rgba8();
    let (tw, th) = tray_rgba.dimensions();
    let tray_icon = TrayIconImage::from_rgba(tray_rgba.into_raw(), tw, th).ok();

    (window_icon, tray_icon)
}

fn show_and_focus(window: &Window) {
    window.set_visible(true);
    window.set_minimized(false);
    #[cfg(target_os = "windows")]
    {
        // Briefly toggle top-most on Windows so returning from browser OAuth reliably
        // raises Wardr above the browser window without staying pinned on top.
        window.set_always_on_top(true);
        window.set_focus();
        window.set_always_on_top(false);
    }
    #[cfg(not(target_os = "windows"))]
    {
        window.set_focus();
    }
}

fn is_allowed_navigation(url: &str, trusted_origin: &Arc<Mutex<Option<String>>>) -> bool {
    if url == "about:blank" || url.starts_with("data:text/html") {
        return true;
    }
    let origin = trusted_origin
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    if let Some(origin) = origin {
        if url == origin || url.starts_with(&format!("{origin}/")) {
            return true;
        }
        if url.starts_with(&format!("blob:{origin}/")) {
            return true;
        }
    }
    false
}

fn open_external_url(url: &str, trusted_origin: &Arc<Mutex<Option<String>>>) {
    let allowed = url.starts_with("https://")
        || trusted_origin
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .is_some_and(|origin| url == origin || url.starts_with(&format!("{origin}/")));
    if allowed {
        let _ = open::that(url);
    }
}

fn suggested_download_name(url: &str, default_path: &std::path::Path) -> String {
    if let Some(name) = default_path.file_name().and_then(|n| n.to_str()) {
        if !name.trim().is_empty() && name != "download" {
            return name.to_string();
        }
    }
    if url.contains("/plan.html") {
        "wardr-plan.html".into()
    } else if url.contains("/plan.json") {
        "wardr-plan.json".into()
    } else if url.contains("/report.html") {
        "wardr-report.html".into()
    } else if url.contains("/report.json") {
        "wardr-report.json".into()
    } else {
        "wardr-export.json".into()
    }
}

fn build_tray_icon(icon: Option<TrayIconImage>) -> Option<TrayIcon> {
    let icon = icon?;
    let tray_menu = Menu::new();
    let open_item = MenuItem::with_id(MENU_ID_OPEN, "Open Wardr", true, None);
    let quit_item = MenuItem::with_id(MENU_ID_QUIT, "Quit Wardr", true, None);
    let _ = tray_menu.append(&open_item);
    let _ = tray_menu.append(&PredefinedMenuItem::separator());
    let _ = tray_menu.append(&quit_item);

    let builder = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_menu_on_left_click(cfg!(target_os = "macos"))
        .with_tooltip("Wardr — Local Security Monitor")
        .with_icon(icon);

    builder.build().ok()
}

#[cfg(target_os = "macos")]
fn setup_macos_menu_bar() -> Menu {
    let menu_bar = Menu::new();

    let app_menu = Submenu::new("Wardr", true);
    let _ = app_menu.append(&PredefinedMenuItem::about(Some("About Wardr"), None));
    let _ = app_menu.append(&PredefinedMenuItem::separator());
    let _ = app_menu.append(&MenuItem::with_id(MENU_ID_OPEN, "Show Wardr", true, None));
    let _ = app_menu.append(&PredefinedMenuItem::hide(Some("Hide Wardr")));
    let _ = app_menu.append(&PredefinedMenuItem::hide_others(None));
    let _ = app_menu.append(&PredefinedMenuItem::show_all(None));
    let _ = app_menu.append(&PredefinedMenuItem::separator());
    let _ = app_menu.append(&MenuItem::with_id(
        MENU_ID_QUIT,
        "Quit Wardr",
        true,
        Some(Accelerator::new(Some(Modifiers::SUPER), Code::KeyQ)),
    ));

    let edit_menu = Submenu::new("Edit", true);
    let _ = edit_menu.append(&PredefinedMenuItem::undo(None));
    let _ = edit_menu.append(&PredefinedMenuItem::redo(None));
    let _ = edit_menu.append(&PredefinedMenuItem::separator());
    let _ = edit_menu.append(&PredefinedMenuItem::cut(None));
    let _ = edit_menu.append(&PredefinedMenuItem::copy(None));
    let _ = edit_menu.append(&PredefinedMenuItem::paste(None));
    let _ = edit_menu.append(&PredefinedMenuItem::select_all(None));

    let view_menu = Submenu::new("View", true);
    let _ = view_menu.append(&MenuItem::with_id(
        MENU_ID_BACK,
        "Back",
        true,
        Some(Accelerator::new(Some(Modifiers::SUPER), Code::BracketLeft)),
    ));
    let _ = view_menu.append(&MenuItem::with_id(
        MENU_ID_FORWARD,
        "Forward",
        true,
        Some(Accelerator::new(Some(Modifiers::SUPER), Code::BracketRight)),
    ));
    let _ = view_menu.append(&PredefinedMenuItem::separator());
    let _ = view_menu.append(&MenuItem::with_id(
        MENU_ID_RELOAD,
        "Reload",
        true,
        Some(Accelerator::new(Some(Modifiers::SUPER), Code::KeyR)),
    ));

    let window_menu = Submenu::new("Window", true);
    let _ = window_menu.append(&PredefinedMenuItem::minimize(None));
    let _ = window_menu.append(&MenuItem::with_id(
        MENU_ID_CLOSE_WIN,
        "Close Window",
        true,
        Some(Accelerator::new(Some(Modifiers::SUPER), Code::KeyW)),
    ));

    let _ = menu_bar.append(&app_menu);
    let _ = menu_bar.append(&edit_menu);
    let _ = menu_bar.append(&view_menu);
    let _ = menu_bar.append(&window_menu);
    menu_bar.init_for_nsapp();
    menu_bar
}

fn create_webview<'a>(
    window: &'a Window,
    web_context: &'a mut WebContext,
    trusted_origin: Arc<Mutex<Option<String>>>,
) -> Result<WebView, wry::Error> {
    let nav_origin = Arc::clone(&trusted_origin);
    let popup_origin = Arc::clone(&trusted_origin);

    let builder = WebViewBuilder::new_with_web_context(web_context)
        .with_html(splash::loading_html(
            "Starting Wardr…",
            "Initializing local security posture checks and real-time sensors.",
        ))
        .with_background_color((13, 36, 27, 255))
        .with_initialization_script("window.__WARDR_DESKTOP__ = true;")
        .with_devtools(cfg!(debug_assertions))
        .with_navigation_handler(move |url| {
            if is_allowed_navigation(&url, &nav_origin) {
                true
            } else {
                open_external_url(&url, &nav_origin);
                false
            }
        })
        .with_new_window_req_handler(move |url, _features| {
            open_external_url(&url, &popup_origin);
            NewWindowResponse::Deny
        })
        .with_download_started_handler(|url, dest_path| {
            let suggested = suggested_download_name(&url, dest_path);
            let mut dialog = rfd::FileDialog::new().set_file_name(&suggested);
            if let Some(parent) = dest_path.parent() {
                if parent.is_dir() {
                    dialog = dialog.set_directory(parent);
                }
            }
            if let Some(chosen) = dialog.save_file() {
                *dest_path = chosen;
                true
            } else {
                false
            }
        });

    #[cfg(target_os = "linux")]
    {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window.default_vbox().expect("GTK window missing default vbox");
        builder.build_gtk(vbox)
    }

    #[cfg(not(target_os = "linux"))]
    {
        builder.build(window)
    }
}

fn wire_event_bridges(proxy: EventLoopProxy<UserEvent>) {
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(UserEvent::MenuAction(event.id.0));
    }));

    let tray_proxy = proxy;
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            let _ = tray_proxy.send_event(UserEvent::TrayClick);
        }
    }));
}

fn show_fatal_dialog(title: &str, message: &str) {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title(title)
        .set_description(message)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

fn main() {
    let cli = match parse_args() {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("Wardr: {message}");
            std::process::exit(2);
        }
    };

    // Headless runtime provisioning path used by macOS release smoke tests and CI.
    if let Some(target_dir) = cli.prepare_only {
        let Some(payload) = backend::bundle_payload_dir() else {
            eprintln!("Wardr: installer payload was not found inside the application bundle.");
            std::process::exit(1);
        };
        if let Err(err) = backend::prepare_payload(&payload, &target_dir) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // Ensure only one Wardr desktop app runs per state directory; focus existing window if already running.
    let focus_proxy = proxy.clone();
    let Some(instance_guard) = instance::acquire_or_focus(cli.backend.state_dir.as_deref(), move || {
        let _ = focus_proxy.send_event(UserEvent::FocusWindow);
    }) else {
        return;
    };
    let mut instance_guard = Some(instance_guard);

    let (window_icon, tray_icon_img) = load_icons();

    #[cfg(target_os = "macos")]
    let _menu_bar = setup_macos_menu_bar();

    let mut window_builder = WindowBuilder::new()
        .with_title("Wardr")
        .with_inner_size(LogicalSize::new(1280.0, 840.0))
        .with_min_inner_size(LogicalSize::new(920.0, 620.0));
    if let Some(icon) = window_icon {
        window_builder = window_builder.with_window_icon(Some(icon));
    }
    let window = match window_builder.build(&event_loop) {
        Ok(win) => win,
        Err(err) => {
            show_fatal_dialog("Wardr could not start", &format!("Could not create window: {err}"));
            return;
        }
    };

    wire_event_bridges(proxy.clone());
    let mut tray_icon = build_tray_icon(tray_icon_img);
    let has_tray = tray_icon.is_some();

    let webview_data_dir = instance::app_data_dir().join("WebView");
    let _ = std::fs::create_dir_all(&webview_data_dir);
    let mut web_context = WebContext::new(Some(webview_data_dir));

    let trusted_origin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let webview = match create_webview(&window, &mut web_context, Arc::clone(&trusted_origin)) {
        Ok(wv) => wv,
        Err(err) => {
            let detail = if cfg!(target_os = "windows") {
                format!(
                    "Wardr requires Microsoft Edge WebView2 Runtime to display its native window.\n\nDetails: {err}"
                )
            } else {
                format!("Wardr could not initialize its native window renderer.\n\nDetails: {err}")
            };
            show_fatal_dialog("Wardr could not start", &detail);
            return;
        }
    };

    let backend_proxy = proxy.clone();
    let supervisor = BackendSupervisor::start(cli.backend, move |event| {
        let _ = backend_proxy.send_event(UserEvent::Backend(event));
    });
    let mut supervisor = Some(supervisor);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::UserEvent(UserEvent::FocusWindow) | Event::UserEvent(UserEvent::TrayClick) => {
                show_and_focus(&window);
            }
            Event::UserEvent(UserEvent::MenuAction(id)) => match id.as_str() {
                MENU_ID_OPEN => {
                    show_and_focus(&window);
                }
                MENU_ID_QUIT => {
                    if let Some(sup) = supervisor.take() {
                        sup.shutdown();
                    }
                    tray_icon.take();
                    instance_guard.take();
                    *control_flow = ControlFlow::Exit;
                }
                #[cfg(target_os = "macos")]
                MENU_ID_BACK => {
                    let _ = webview.evaluate_script("window.history.back()");
                }
                #[cfg(target_os = "macos")]
                MENU_ID_FORWARD => {
                    let _ = webview.evaluate_script("window.history.forward()");
                }
                #[cfg(target_os = "macos")]
                MENU_ID_RELOAD => {
                    let _ = webview.evaluate_script("window.location.reload()");
                }
                #[cfg(target_os = "macos")]
                MENU_ID_CLOSE_WIN => {
                    if has_tray {
                        window.set_visible(false);
                    } else {
                        if let Some(sup) = supervisor.take() {
                            sup.shutdown();
                        }
                        instance_guard.take();
                        *control_flow = ControlFlow::Exit;
                    }
                }
                _ => {}
            },
            Event::UserEvent(UserEvent::Backend(backend_event)) => match backend_event {
                BackendEvent::Status { headline, detail } => {
                    let _ = webview.load_html(&splash::loading_html(&headline, &detail));
                }
                BackendEvent::Ready { origin, launch_url } => {
                    if let Ok(mut guard) = trusted_origin.lock() {
                        *guard = Some(origin);
                    }
                    let _ = webview.load_url(&launch_url);
                }
                BackendEvent::FocusWindow => {
                    show_and_focus(&window);
                    let _ = webview.evaluate_script("if (window.__wardrOnFocus) window.__wardrOnFocus();");
                }
                BackendEvent::Restarting => {
                    if let Ok(mut guard) = trusted_origin.lock() {
                        *guard = None;
                    }
                    let _ = webview.load_html(&splash::loading_html(
                        "Restarting Wardr…",
                        "Applying your verified update and reconnecting automatically.",
                    ));
                }
                BackendEvent::Failed(message) => {
                    show_and_focus(&window);
                    let _ = webview.load_html(&splash::error_html("Wardr could not start", &message));
                }
            },
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if has_tray {
                    // Keep Wardr running in the system tray / menu bar for continuous monitoring.
                    window.set_visible(false);
                } else {
                    if let Some(sup) = supervisor.take() {
                        sup.shutdown();
                    }
                    instance_guard.take();
                    *control_flow = ControlFlow::Exit;
                }
            }
            #[cfg(target_os = "macos")]
            Event::Reopen { .. } => {
                show_and_focus(&window);
            }
            Event::LoopDestroyed => {
                if let Some(sup) = supervisor.take() {
                    sup.shutdown();
                }
                tray_icon.take();
                instance_guard.take();
            }
            _ => {}
        }
    });
}
