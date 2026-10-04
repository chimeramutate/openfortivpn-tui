use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
        KeyModifiers, MouseButton, MouseEventKind,
    },
    execute,
};
use ratatui::DefaultTerminal;

use crate::{
    actions,
    app::{App, AppEvent, Focus, NotifLevel, UiMode, VpnState},
    config::Config,
    ui, vpn,
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

    spawn_network_watcher(app.event_tx.clone());

    // ratatui::init also installs a panic hook that restores the terminal.
    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), EnableMouseCapture)?;

    let result = run_app(&mut terminal, &mut app).await;

    actions::save_all_config(&app).ok();

    execute!(std::io::stdout(), DisableMouseCapture)?;
    ratatui::restore();
    if let Err(e) = result {
        eprintln!("Error: {}", e);
    }
    Ok(())
}

fn spawn_network_watcher(tx: tokio::sync::mpsc::UnboundedSender<AppEvent>) {
    tokio::spawn(async move {
        let mut online = true;
        loop {
            let now = vpn::has_physical_network();
            if now != online {
                online = now;
                if tx.send(AppEvent::NetworkChanged(now)).is_err() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn run_app(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let tick_rate = Duration::from_millis(100);
    loop {
        terminal.draw(|f| ui::render(f, app))?;
        drain_events(app).await?;
        if event::poll(tick_rate)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key).await?,
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        actions::handle_click(app, mouse.column, mouse.row).await?
                    }
                    MouseEventKind::ScrollUp if app.ui_mode == UiMode::ProfileList => {
                        handle_key(app, KeyCode::Up.into()).await?
                    }
                    MouseEventKind::ScrollDown if app.ui_mode == UiMode::ProfileList => {
                        handle_key(app, KeyCode::Down.into()).await?
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        app.tick_notification();
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

async fn drain_events(app: &mut App) -> Result<()> {
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
                AppEvent::NetworkChanged(online) => {
                    actions::handle_network_change(app, online).await?
                }
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
                AppEvent::InterfaceDetected {
                    session_id,
                    interface,
                } => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    app.sessions[idx].vpn_interface = Some(interface);
                }
                AppEvent::StateChanged {
                    session_id,
                    state: mut new_state,
                } => {
                    let Some(idx) = app.find_session_index_by_id(session_id) else {
                        continue;
                    };
                    let old = app.sessions[idx].vpn_state.clone();
                    let dropped_by_network = matches!(
                        old,
                        VpnState::Connected | VpnState::Connecting | VpnState::WaitingToken
                    ) && matches!(new_state, VpnState::Error(_) | VpnState::Disconnected)
                        && !vpn::has_physical_network();
                    if dropped_by_network {
                        // Tunnel died before the watcher noticed; treat as a network drop.
                        app.sessions[idx].reconnect_on_network = true;
                        app.network_online = false;
                    }
                    if (dropped_by_network || old == VpnState::Disconnecting)
                        && matches!(new_state, VpnState::Error(_))
                    {
                        // Non-zero exit after we killed it (or the network vanished) is not a failure.
                        new_state = VpnState::Disconnected;
                    }
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
                            let failed_before_connected = !dropped_by_network
                                && matches!(old, VpnState::Connecting | VpnState::WaitingToken)
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
                            actions::reconnect_dropped_sessions(app).await?;
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
                    if dropped_by_network {
                        app.notify(
                            "Koneksi jaringan (WiFi) terputus - VPN akan reconnect otomatis",
                            NotifLevel::Error,
                        );
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
    Ok(())
}

pub async fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) -> Result<()> {
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
