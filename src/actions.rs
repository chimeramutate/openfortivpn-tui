use std::time::Duration;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    app::{App, AppEvent, Focus, NotifLevel, PendingAction, UiMode, VpnState, profile_form},
    config::{self, Config},
    vpn,
};

fn load_config_or_notify(app: &mut App, action: &str) -> Option<Config> {
    match Config::load() {
        Ok(cfg) => Some(cfg),
        Err(err) => {
            let message = format!("{action} dibatalkan: {err}");
            app.notify(message.clone(), NotifLevel::Error);
            app.push_log(format!("[APP] {message}"));
            None
        }
    }
}

pub async fn handle_profile_list_mode(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Up if app.selected_profile_index > 0 => {
            app.selected_profile_index -= 1;
            app.select_profile(app.selected_profile_index);
        }
        KeyCode::Down if app.selected_profile_index + 1 < app.profiles.len() => {
            app.selected_profile_index += 1;
            app.select_profile(app.selected_profile_index);
        }
        KeyCode::Enter | KeyCode::F(5) => {
            let profile_name = app.get_current_profile().map(|p| p.name.clone());
            if let Some(name) = profile_name {
                if let Some(idx) = app.find_session_by_profile_name(&name) {
                    app.activate_session(idx);
                    app.notify(format!("Membuka session '{}'", name), NotifLevel::Info);
                    app.push_log(format!("[APP] Membuka session existing: {}", name));
                } else {
                    app.ui_mode = UiMode::Connect;
                    app.apply_current_profile();
                    app.push_log(format!("[APP] Menggunakan profile: {}", name));
                    let _ = do_connect(app).await;
                }
            }
        }
        KeyCode::F(2) | KeyCode::Char('n') | KeyCode::Char('N') => {
            profile_form::start_new(app);
            app.push_log("[APP] Mode: New Profile (F2/N)");
        }
        KeyCode::F(3) | KeyCode::Char('e') | KeyCode::Char('E') => {
            if let Some(profile) = app.get_current_profile().cloned() {
                let profile_name = profile.name.clone();
                profile_form::start_edit(app, &profile);
                app.push_log(format!(
                    "[APP] Mode: Edit Profile '{}' (F3/E)",
                    profile_name
                ));
            }
        }
        KeyCode::F(4) | KeyCode::Char('d') | KeyCode::Char('D') => {
            if let Some(profile) = app.get_current_profile() {
                let profile_name = profile.name.clone();
                if app.delete_confirmation.is_some() {
                    if app.delete_confirmation.as_ref() == Some(&profile_name) {
                        let Some(mut cfg) = load_config_or_notify(app, "Hapus profile") else {
                            app.delete_confirmation = None;
                            return Ok(());
                        };
                        cfg.delete_profile(&profile_name);
                        if let Err(e) = cfg.save() {
                            app.notify(format!("Gagal hapus: {}", e), NotifLevel::Error);
                        } else {
                            app.profiles = cfg.profiles;
                            app.selected_profile_index = app
                                .selected_profile_index
                                .min(app.profiles.len().saturating_sub(1));
                            app.notify(
                                format!("Profile '{}' dihapus", profile_name),
                                NotifLevel::Success,
                            );
                            app.push_log(format!(
                                "[APP] Profile '{}' dihapus (F4/D)",
                                profile_name
                            ));
                        }
                        app.delete_confirmation = None;
                    } else {
                        app.delete_confirmation = None;
                    }
                } else {
                    app.delete_confirmation = Some(profile_name.clone());
                    app.notify(
                        format!("Tekan F4 atau D lagi untuk hapus '{}'", profile_name),
                        NotifLevel::Warning,
                    );
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub async fn handle_profile_form_mode(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Tab => match app.focus {
            Focus::ProfileName => app.focus = Focus::Host,
            Focus::Host => app.focus = Focus::Port,
            Focus::Port => app.focus = Focus::Username,
            Focus::Username => app.focus = Focus::Password,
            Focus::Password => app.focus = Focus::SudoPassword,
            Focus::SudoPassword => app.focus = Focus::SavePassword,
            Focus::SavePassword => app.focus = Focus::UseSudoPassword,
            Focus::UseSudoPassword => app.focus = Focus::ProfileName,
            _ => app.focus = Focus::ProfileName,
        },
        KeyCode::BackTab => match app.focus {
            Focus::ProfileName => app.focus = Focus::UseSudoPassword,
            Focus::Host => app.focus = Focus::ProfileName,
            Focus::Port => app.focus = Focus::Host,
            Focus::Username => app.focus = Focus::Port,
            Focus::Password => app.focus = Focus::Username,
            Focus::SudoPassword => app.focus = Focus::Password,
            Focus::SavePassword => app.focus = Focus::SudoPassword,
            Focus::UseSudoPassword => app.focus = Focus::SavePassword,
            _ => app.focus = Focus::ProfileName,
        },
        KeyCode::Char(' ') => {
            if app.focus == Focus::SavePassword {
                app.profile_save_password = !app.profile_save_password;
                if !app.profile_save_password {
                    app.profile_password.clear();
                }
            } else if app.focus == Focus::UseSudoPassword {
                app.profile_use_sudo_password = !app.profile_use_sudo_password;
                if !app.profile_use_sudo_password {
                    app.profile_sudo_password.clear();
                }
            }
        }
        KeyCode::Enter => save_profile(app).await?,
        KeyCode::Esc => {
            app.ui_mode = UiMode::ProfileList;
            app.focus = Focus::ProfileList;
            app.delete_confirmation = None;
            app.push_log("[APP] Kembali ke daftar profile");
        }
        _ => match app.focus {
            Focus::ProfileName => handle_text_input(&mut app.profile_name, key),
            Focus::Host => handle_text_input(&mut app.profile_host, key),
            Focus::Port => handle_text_input(&mut app.profile_port, key),
            Focus::Username => handle_text_input(&mut app.profile_username, key),
            Focus::Password => handle_text_input(&mut app.profile_password, key),
            Focus::SudoPassword => handle_text_input(&mut app.profile_sudo_password, key),
            _ => {}
        },
    }
    Ok(())
}

pub async fn handle_connect_mode(app: &mut App, key: KeyEvent) -> Result<()> {
    match (key.modifiers, key.code) {
        (KeyModifiers::CONTROL, KeyCode::Char('k')) => {
            app.request_action_confirmation(PendingAction::DisconnectActive);
            return Ok(());
        }
        (mods, KeyCode::Char('K'))
            if mods.contains(KeyModifiers::CONTROL) && mods.contains(KeyModifiers::SHIFT) =>
        {
            app.request_action_confirmation(PendingAction::DisconnectAll);
            return Ok(());
        }
        (_, KeyCode::Left) => {
            app.activate_prev_session();
            return Ok(());
        }
        (_, KeyCode::Right) => {
            app.activate_next_session();
            return Ok(());
        }
        (KeyModifiers::CONTROL, KeyCode::Char('w')) => {
            app.request_action_confirmation(PendingAction::CloseActive);
            return Ok(());
        }
        (mods, KeyCode::Char('W'))
            if mods.contains(KeyModifiers::CONTROL) && mods.contains(KeyModifiers::SHIFT) =>
        {
            app.request_action_confirmation(PendingAction::CloseAllIdle);
            return Ok(());
        }
        (_, KeyCode::Tab) => {
            app.cycle_focus_forward();
            return Ok(());
        }
        (KeyModifiers::SHIFT, KeyCode::BackTab) => {
            app.cycle_focus_backward();
            return Ok(());
        }
        _ => {
            if app.focus == Focus::Connect && key.code == KeyCode::Enter {
                do_connect(app).await?;
            } else if app.focus == Focus::Disconnect && key.code == KeyCode::Enter {
                do_disconnect(app).await?;
            }
        }
    }
    Ok(())
}

pub async fn handle_token_popup(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char(c) => {
            if let Some(session) = app.active_session_mut() {
                session.token_input.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(session) = app.active_session_mut() {
                session.token_input.pop();
            }
        }
        KeyCode::Delete => {
            if let Some(session) = app.active_session_mut() {
                session.token_input.clear();
            }
        }
        KeyCode::Enter => {
            let Some((session_id, token, pid_store, stdin_store, waiting_flag)) =
                app.active_session().map(|session| {
                    (
                        session.id,
                        session.token_input.trim().to_string(),
                        session.vpn_pid.clone(),
                        session.vpn_stdin.clone(),
                        session.waiting_for_input_flag.clone(),
                    )
                })
            else {
                return Ok(());
            };
            if token.is_empty() {
                app.notify("Token tidak boleh kosong!", NotifLevel::Error);
                return Ok(());
            }

            app.push_log("[TOKEN] Mengirim token OTP...");

            let event_tx = app.event_tx.clone();

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                match vpn::send_token(session_id, &token, pid_store, stdin_store, event_tx.clone())
                    .await
                {
                    Ok(_) => {
                        let _ = event_tx.send(AppEvent::LogLine {
                            session_id,
                            line: "[TOKEN] Token terkirim".into(),
                        });
                    }
                    Err(e) => {
                        let _ = event_tx.send(AppEvent::LogLine {
                            session_id,
                            line: format!("[TOKEN] Gagal: {}", e),
                        });
                    }
                }
                *waiting_flag.lock().unwrap() = false;
            });

            if let Some(session) = app.active_session_mut() {
                session.token_input.clear();
                session.vpn_state = VpnState::Connecting;
            }
            app.focus = Focus::Disconnect;
        }
        KeyCode::Esc => {
            if let Some(session) = app.active_session_mut() {
                session.token_input.clear();
            }
            app.push_log("[TOKEN] Token dibatalkan");
            if let Some(session) = app.active_session() {
                *session.waiting_for_input_flag.lock().unwrap() = false;
            }
            do_disconnect(app).await?;
        }
        _ => {}
    }
    Ok(())
}

pub async fn handle_action_confirm_popup(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
            app.cycle_focus_forward();
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            execute_pending_action(app).await?;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.clear_action_confirmation();
            app.notify("Aksi dibatalkan", NotifLevel::Info);
        }
        KeyCode::Enter => {
            if app.focus == Focus::ActionConfirmAccept {
                execute_pending_action(app).await?;
            } else {
                app.clear_action_confirmation();
                app.notify("Aksi dibatalkan", NotifLevel::Info);
            }
        }
        _ => {}
    }
    Ok(())
}

async fn execute_pending_action(app: &mut App) -> Result<()> {
    let Some(action) = app.pending_action.clone() else {
        return Ok(());
    };
    app.pending_action = None;
    match action {
        PendingAction::DisconnectActive => do_disconnect(app).await?,
        PendingAction::DisconnectAll => disconnect_all_sessions(app),
        PendingAction::CloseActive => close_active_session(app)?,
        PendingAction::CloseAllIdle => close_all_sessions(app),
    }
    Ok(())
}

pub async fn handle_cert_dialog(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Tab | KeyCode::Right | KeyCode::Left => {
            app.focus = match app.focus {
                Focus::CertAccept => Focus::CertDeny,
                _ => Focus::CertAccept,
            };
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            accept_cert_and_reconnect(app).await?;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            deny_cert(app);
        }
        KeyCode::Enter => {
            if app.focus == Focus::CertAccept {
                accept_cert_and_reconnect(app).await?;
            } else {
                deny_cert(app);
            }
        }
        _ => {}
    }
    Ok(())
}

async fn accept_cert_and_reconnect(app: &mut App) -> Result<()> {
    let Some(session) = app.active_session_mut() else {
        return Ok(());
    };
    let cert = match session.pending_cert.take() {
        Some(c) => c,
        None => return Ok(()),
    };
    let profile_name = session.profile_name.clone();
    session.push_log(format!("[CERT] Certificate diterima: {}", cert.subject_cn));
    session.trusted_cert = Some(cert.hash.clone());
    session.reset_connection_metrics();
    session.vpn_state = VpnState::Connecting;
    let session_id = session.id;
    let host = session.host.clone();
    let port = session.port;
    let username = session.username.clone();
    let password = session.password.clone();
    let sudo_pwd = if session.sudo_password.is_empty() {
        None
    } else {
        Some(session.sudo_password.clone())
    };
    let pid_store = session.vpn_pid.clone();
    let stdin_store = session.vpn_stdin.clone();
    let input_flag = session.waiting_for_input_flag.clone();

    app.update_profile_trusted_cert(&profile_name, &cert.hash);
    save_all_config(app).ok();
    app.focus = Focus::Disconnect;
    app.push_log("[APP] Menghubungkan ulang dengan cert trusted...");

    let trusted_cert = Some(cert.hash);
    let event_tx = app.event_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = vpn::connect(
            session_id,
            &host,
            port,
            &username,
            &password,
            sudo_pwd,
            trusted_cert,
            event_tx.clone(),
            pid_store,
            stdin_store,
            input_flag,
        )
        .await
        {
            let _ = event_tx.send(AppEvent::LogLine {
                session_id,
                line: format!("[APP] Gagal connect ulang: {}", e),
            });
            let _ = event_tx.send(AppEvent::StateChanged {
                session_id,
                state: VpnState::Error(e.to_string()),
            });
        }
    });
    Ok(())
}

fn deny_cert(app: &mut App) {
    let cn = app
        .active_session()
        .and_then(|s| s.pending_cert.as_ref().map(|c| c.subject_cn.clone()))
        .unwrap_or_default();
    app.push_log(format!("[CERT] Certificate ditolak: {}", cn));
    if let Some(session) = app.active_session_mut() {
        session.pending_cert = None;
        *session.waiting_for_input_flag.lock().unwrap() = false;
        session.vpn_state = VpnState::Disconnected;
    }
    app.focus = Focus::Connect;
    app.notify(
        "Certificate ditolak. Koneksi dibatalkan.",
        NotifLevel::Warning,
    );
}

fn handle_text_input(field: &mut String, key: KeyEvent) {
    match key.code {
        KeyCode::Char(c) => field.push(c),
        KeyCode::Backspace => {
            field.pop();
        }
        KeyCode::Delete => field.clear(),
        _ => {}
    }
}

async fn do_connect(app: &mut App) -> Result<()> {
    if app.active_session_index.is_none() {
        let Some(session_id) = app.ensure_session_for_selected_profile() else {
            app.notify("Pilih profile terlebih dahulu", NotifLevel::Warning);
            return Ok(());
        };
        if let Some(idx) = app.find_session_index_by_id(session_id) {
            app.activate_session(idx);
        }
    }

    let Some(session) = app.active_session() else {
        return Ok(());
    };
    if !matches!(
        session.vpn_state,
        VpnState::Disconnected | VpnState::Error(_)
    ) {
        app.notify(
            "Sudah terhubung atau sedang menghubungkan",
            NotifLevel::Warning,
        );
        return Ok(());
    }
    if session.host.is_empty() || session.username.is_empty() || session.password.is_empty() {
        app.notify(
            "Host, Username, dan Password harus diisi",
            NotifLevel::Error,
        );
        return Ok(());
    }

    let session_id = session.id;
    let profile_name = session.profile_name.clone();
    let host = session.host.clone();
    let port = session.port;
    let username = session.username.clone();
    let password = session.password.clone();
    let trusted_cert = session.trusted_cert.clone();
    let sudo_pwd = if session.sudo_password.is_empty() {
        None
    } else {
        Some(session.sudo_password.clone())
    };
    let pid_store = session.vpn_pid.clone();
    let stdin_store = session.vpn_stdin.clone();
    let input_flag = session.waiting_for_input_flag.clone();

    if let Some(session) = app.active_session_mut() {
        session.reset_connection_metrics();
        session.vpn_state = VpnState::Connecting;
    }
    app.push_log(format!("[APP] Menghubungkan profile '{}'...", profile_name));
    if trusted_cert.is_some() {
        app.push_log("[APP] Menggunakan trusted cert yang tersimpan");
    }
    app.notify("Menghubungkan ke VPN...", NotifLevel::Info);

    let event_tx = app.event_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = vpn::connect(
            session_id,
            &host,
            port,
            &username,
            &password,
            sudo_pwd,
            trusted_cert,
            event_tx.clone(),
            pid_store,
            stdin_store,
            input_flag,
        )
        .await
        {
            let _ = event_tx.send(AppEvent::LogLine {
                session_id,
                line: format!("[APP] Gagal: {}", e),
            });
            let _ = event_tx.send(AppEvent::StateChanged {
                session_id,
                state: VpnState::Error(e.to_string()),
            });
        }
    });
    Ok(())
}

async fn do_disconnect(app: &mut App) -> Result<()> {
    let Some(session) = app.active_session() else {
        app.notify("Tidak ada session aktif", NotifLevel::Info);
        return Ok(());
    };
    if matches!(session.vpn_state, VpnState::Disconnected) {
        app.notify("Tidak ada koneksi aktif", NotifLevel::Info);
        return Ok(());
    }

    let session_id = session.id;
    let pid_store = session.vpn_pid.clone();
    let stdin_store = session.vpn_stdin.clone();
    if let Some(session) = app.active_session_mut() {
        session.token_input.clear();
        session.pending_cert = None;
        session.rx_speed_bps = 0;
        session.tx_speed_bps = 0;
        *session.waiting_for_input_flag.lock().unwrap() = false;
        session.vpn_state = VpnState::Disconnecting;
    }
    app.focus = Focus::Connect;
    app.push_log("[APP] Memutuskan koneksi VPN...");
    app.notify("Memutuskan koneksi...", NotifLevel::Warning);

    let event_tx = app.event_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = vpn::disconnect(session_id, pid_store, stdin_store, event_tx.clone()).await
        {
            let _ = event_tx.send(AppEvent::LogLine {
                session_id,
                line: format!("[APP] Gagal disconnect: {}", e),
            });
        }
    });
    Ok(())
}

fn close_active_session(app: &mut App) -> Result<()> {
    let Some(session) = app.active_session() else {
        return Ok(());
    };
    match session.vpn_state {
        VpnState::Disconnected | VpnState::Error(_) => {
            let name = session.profile_name.clone();
            app.close_active_session();
            app.notify(format!("Session '{}' ditutup", name), NotifLevel::Info);
        }
        _ => {
            app.notify(
                "Disconnect session aktif dulu sebelum close tab",
                NotifLevel::Warning,
            );
        }
    }
    Ok(())
}

fn close_all_sessions(app: &mut App) {
    let before = app.sessions.len();
    app.sessions.retain(|session| {
        !matches!(
            session.vpn_state,
            VpnState::Disconnected | VpnState::Error(_)
        )
    });
    let removed = before.saturating_sub(app.sessions.len());

    if app.sessions.is_empty() {
        app.active_session_index = None;
        app.ui_mode = UiMode::ProfileList;
        app.focus = Focus::ProfileList;
    } else if let Some(active_idx) = app.active_session_index
        && active_idx >= app.sessions.len()
    {
        app.activate_session(app.sessions.len().saturating_sub(1));
    }

    if removed > 0 {
        app.notify(format!("{} session ditutup", removed), NotifLevel::Info);
    } else {
        app.notify("Tidak ada session yang bisa ditutup", NotifLevel::Warning);
    }
}

fn disconnect_all_sessions(app: &mut App) {
    let event_tx = app.event_tx.clone();
    let mut count = 0usize;

    for session in app.sessions.iter_mut() {
        if matches!(
            session.vpn_state,
            VpnState::Connected
                | VpnState::Connecting
                | VpnState::WaitingToken
                | VpnState::WaitingCert
        ) {
            let session_id = session.id;
            let pid_store = session.vpn_pid.clone();
            let stdin_store = session.vpn_stdin.clone();
            session.token_input.clear();
            session.pending_cert = None;
            session.rx_speed_bps = 0;
            session.tx_speed_bps = 0;
            *session.waiting_for_input_flag.lock().unwrap() = false;
            session.vpn_state = VpnState::Disconnecting;
            count += 1;

            let tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    vpn::disconnect(session_id, pid_store, stdin_store, tx.clone()).await
                {
                    let _ = tx.send(AppEvent::LogLine {
                        session_id,
                        line: format!("[APP] Gagal disconnect: {}", e),
                    });
                }
            });
        }
    }

    if count > 0 {
        app.focus = Focus::Connect;
        app.notify(
            format!("Memutuskan {} session...", count),
            NotifLevel::Warning,
        );
        app.push_log(format!("[APP] Memutuskan {} session aktif...", count));
    } else {
        app.notify("Tidak ada session aktif untuk diputus", NotifLevel::Info);
    }
}

async fn save_profile(app: &mut App) -> Result<()> {
    if app.profile_name.trim().is_empty() {
        app.notify("Nama profile tidak boleh kosong!", NotifLevel::Error);
        return Ok(());
    }
    if app.profile_host.trim().is_empty() {
        app.notify("Host tidak boleh kosong!", NotifLevel::Error);
        return Ok(());
    }

    let port: u16 = app.profile_port.parse().unwrap_or(443);
    let new_profile = config::VpnProfile {
        name: app.profile_name.clone(),
        host: app.profile_host.clone(),
        port,
        username: app.profile_username.clone(),
        save_password: app.profile_save_password,
        password: if app.profile_save_password {
            app.profile_password.clone()
        } else {
            String::new()
        },
        trusted_cert: None,
        use_sudo_password: app.profile_use_sudo_password,
        sudo_password: if app.profile_use_sudo_password {
            app.profile_sudo_password.clone()
        } else {
            String::new()
        },
    };

    let Some(mut cfg) = load_config_or_notify(app, "Simpan profile") else {
        return Ok(());
    };
    let is_edit = app.ui_mode == UiMode::EditProfile;
    let old_name = app.editing_profile_name.clone();

    if is_edit && let Some(old_name) = &old_name {
        cfg.delete_profile(old_name);
    }

    cfg.add_profile(new_profile);

    if let Err(e) = cfg.save() {
        app.notify(format!("Gagal simpan: {}", e), NotifLevel::Error);
        return Ok(());
    }

    app.profiles = cfg.profiles;
    app.selected_profile_index = app
        .profiles
        .iter()
        .position(|p| p.name == app.profile_name)
        .unwrap_or(0);

    app.ui_mode = UiMode::ProfileList;
    app.focus = Focus::ProfileList;
    app.delete_confirmation = None;

    app.notify(
        format!("Profile '{}' tersimpan!", app.profile_name),
        NotifLevel::Success,
    );
    app.push_log(format!("[APP] Profile '{}' tersimpan", app.profile_name));
    Ok(())
}

pub fn save_all_config(app: &App) -> Result<()> {
    let cfg = Config {
        profiles: app.profiles.clone(),
        selected_profile: app.get_current_profile().map(|p| p.name.clone()),
    };
    cfg.save()?;
    Ok(())
}

pub fn setup_logging(debug_enabled: bool) -> Result<()> {
    if !debug_enabled {
        return Ok(());
    }

    use std::fs::OpenOptions;
    let log_file = std::env::temp_dir().join("openfortivpn-tui.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)?;
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false);
    tracing_subscriber::registry().with(file_layer).init();
    Ok(())
}
