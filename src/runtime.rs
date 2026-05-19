use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    actions,
    app::{App, AppEvent, Focus, NotifLevel, UiMode, VpnState},
    config::Config,
    ui,
};

pub async fn run() -> Result<()> {
    let debug_enabled = std::env::args().any(|arg| arg == "-d" || arg == "--debug");
    actions::setup_logging(debug_enabled)?;
    let cfg = Config::load()?;
    let mut app = App::new(debug_enabled);

    app.load_profiles(cfg.profiles.clone());
    if let Some(selected) = cfg.selected_profile
        && let Some(idx) = app.profiles.iter().position(|p| p.name == selected)
    {
        app.selected_profile_index = idx;
        app.select_profile(idx);
    }

    if app.profiles.is_empty() {
        app.ui_mode = UiMode::NewProfile;
        app.focus = Focus::ProfileName;
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_app(&mut terminal, &mut app).await;

    actions::save_all_config(&app).ok();

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(100);
    loop {
        terminal.draw(|f| ui::render(f, app))?;
        drain_events(app).await;
        if event::poll(tick_rate)?
            && let Event::Key(key) = event::read()?
        {
            handle_key(app, key).await?;
        }
        app.tick_notification();
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

async fn drain_events(app: &mut App) {
    use tokio::sync::mpsc::error::TryRecvError;
    loop {
        match app.event_rx.try_recv() {
            Ok(event) => match event {
                AppEvent::LogLine { session_id, line } => {
                    if let Some(idx) = app.find_session_index_by_id(session_id) {
                        let is_active = app.active_session_index == Some(idx);
                        if let Some(session) = app.sessions.get_mut(idx) {
                            tracing::info!("{}", line);
                            session.push_log(line);
                        }
                        if is_active && matches!(app.focus, Focus::ProfileList) {
                            app.focus = Focus::Connect;
                        }
                    } else {
                        app.push_log(line);
                    }
                }
                AppEvent::DebugLog(line) => app.push_debug_log(line),
                AppEvent::SpeedUpdate {
                    session_id,
                    interface,
                    rx_bps,
                    tx_bps,
                    rx_total,
                    tx_total,
                } => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    let session = &mut app.sessions[idx];
                    session.vpn_interface = Some(interface);
                    session.rx_speed_bps = rx_bps;
                    session.tx_speed_bps = tx_bps;
                    session.rx_total_bytes = rx_total;
                    session.tx_total_bytes = tx_total;
                }
                AppEvent::StateChanged {
                    session_id,
                    state: new_state,
                } => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    let old = app.sessions[idx].vpn_state.clone();
                    app.sessions[idx].vpn_state = new_state.clone();
                    let is_active = app.active_session_index == Some(idx);
                    match (&old, &new_state) {
                        (_, VpnState::Connected) => {
                            let profile_name = app.sessions[idx].profile_name.clone();
                            if app.sessions[idx].connected_at.is_none() {
                                app.sessions[idx].connected_at = Some(Instant::now());
                            }
                            app.connection_error = None;
                            app.notify(
                                format!("VPN '{}' terhubung!", profile_name),
                                NotifLevel::Success,
                            );
                            app.sessions[idx].push_log("[APP] Koneksi VPN berhasil");
                            if is_active {
                                app.focus = Focus::Disconnect;
                            }
                            *app.sessions[idx].waiting_for_input_flag.lock().unwrap() = false;
                        }
                        (_, VpnState::Disconnected) => {
                            let failed_before_connected =
                                matches!(old, VpnState::Connecting | VpnState::WaitingToken)
                                    && app.sessions[idx].connected_at.is_none();
                            app.sessions[idx].connected_at = None;
                            app.sessions[idx].rx_speed_bps = 0;
                            app.sessions[idx].tx_speed_bps = 0;
                            if failed_before_connected {
                                let profile_name = app.sessions[idx].profile_name.clone();
                                app.show_connection_error(format!(
                                    "Gagal terkoneksi ke VPN '{}'",
                                    profile_name
                                ));
                            }
                            if !matches!(old, VpnState::Disconnected | VpnState::WaitingCert) {
                                let profile_name = app.sessions[idx].profile_name.clone();
                                if !failed_before_connected {
                                    app.notify(
                                        format!("VPN '{}' terputus", profile_name),
                                        NotifLevel::Warning,
                                    );
                                }
                                app.sessions[idx].push_log("[APP] VPN terputus");
                            }
                            if is_active && app.has_modal() {
                                app.focus = Focus::Connect;
                            }
                            *app.sessions[idx].waiting_for_input_flag.lock().unwrap() = false;
                        }
                        (_, VpnState::Error(e)) => {
                            let profile_name = app.sessions[idx].profile_name.clone();
                            app.sessions[idx].connected_at = None;
                            app.sessions[idx].rx_speed_bps = 0;
                            app.sessions[idx].tx_speed_bps = 0;
                            app.show_connection_error(format!(
                                "Gagal terkoneksi ke VPN '{}': {}",
                                profile_name, e
                            ));
                            app.notify(
                                format!("Error '{}': {}", profile_name, e),
                                NotifLevel::Error,
                            );
                            app.sessions[idx].push_log(format!("[APP] Error: {}", e));
                            *app.sessions[idx].waiting_for_input_flag.lock().unwrap() = false;
                        }
                        _ => {}
                    }
                }
                AppEvent::NeedToken(session_id) => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    if app.sessions[idx].vpn_state == VpnState::WaitingToken {
                        continue;
                    }
                    app.sessions[idx].vpn_state = VpnState::WaitingToken;
                    app.sessions[idx].token_input.clear();
                    app.sessions[idx]
                        .push_log("[APP] Token OTP diminta - masukkan token dari email");
                    app.notify(
                        format!(
                            "Masukkan token OTP untuk '{}'",
                            app.sessions[idx].profile_name
                        ),
                        NotifLevel::Info,
                    );
                    *app.sessions[idx].waiting_for_input_flag.lock().unwrap() = true;
                    app.activate_session(idx);
                    app.focus = Focus::TokenInput;
                }
                AppEvent::CertError { session_id, cert } => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    app.sessions[idx].push_log(format!(
                        "[CERT] Peringatan: Certificate tidak dipercaya: CN={}",
                        cert.subject_cn
                    ));
                    app.sessions[idx].pending_cert = Some(cert);
                    app.sessions[idx].vpn_state = VpnState::WaitingCert;
                    app.activate_session(idx);
                    app.focus = Focus::CertAccept;
                }
            },
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }
}

async fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) -> Result<()> {
    if app.connection_error.is_some() {
        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            app.clear_connection_error();
        }
        return Ok(());
    }

    if app.ui_mode == UiMode::Help {
        if key.code == KeyCode::Esc || key.code == KeyCode::F(1) {
            app.hide_help();
        }
        return Ok(());
    }

    if key.code == KeyCode::F(1) {
        app.show_help();
        return Ok(());
    }

    if matches!(
        (key.modifiers, key.code),
        (KeyModifiers::CONTROL, KeyCode::Char('c')) | (KeyModifiers::CONTROL, KeyCode::Char('q'))
    ) {
        app.should_quit = true;
        return Ok(());
    }

    if app.pending_action.is_some() {
        return actions::handle_action_confirm_popup(app, key).await;
    }
    if app.active_session_state() == VpnState::WaitingToken {
        return actions::handle_token_popup(app, key).await;
    }
    if app.active_session_state() == VpnState::WaitingCert {
        return actions::handle_cert_dialog(app, key).await;
    }

    if key.code == KeyCode::Esc
        || matches!(
            (key.modifiers, key.code),
            (KeyModifiers::CONTROL, KeyCode::Char('b'))
        )
    {
        app.back_to_profile_list();
        return Ok(());
    }

    match app.ui_mode {
        UiMode::ProfileList => actions::handle_profile_list_mode(app, key).await?,
        UiMode::NewProfile | UiMode::EditProfile => {
            actions::handle_profile_form_mode(app, key).await?
        }
        UiMode::Connect => actions::handle_connect_mode(app, key).await?,
        UiMode::Help => {}
    }

    Ok(())
}
