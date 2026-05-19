use crate::app::{App, Focus, NotifLevel, PendingAction, UiMode, VpnState};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Padding, Paragraph},
};
use std::time::Duration;

// --- Palette -----------------------------------------------------------------
const C_BG: Color = Color::Rgb(18, 18, 28);
const C_SURFACE: Color = Color::Rgb(28, 28, 42);
const C_BORDER: Color = Color::Rgb(60, 60, 90);
const C_FOCUS: Color = Color::Rgb(100, 180, 255);
const C_TEXT: Color = Color::Rgb(220, 220, 240);
const C_DIM: Color = Color::Rgb(100, 100, 130);
const C_GREEN: Color = Color::Rgb(80, 220, 120);
const C_RED: Color = Color::Rgb(255, 80, 80);
const C_YELLOW: Color = Color::Rgb(255, 210, 60);
const C_ORANGE: Color = Color::Rgb(255, 140, 40);
const C_CYAN: Color = Color::Rgb(60, 210, 210);
// --- Main render entry --------------------------------------------------------
pub fn render(f: &mut Frame, app: &App) {
    let full = f.area();
    f.render_widget(Block::default().style(Style::default().bg(C_BG)), full);

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(full);

    render_title(f, app, outer[0]);
    render_body(f, app, outer[1]);
    render_statusbar(f, app, outer[2]);

    // Modal popups (di atas semua layer)
    if app.ui_mode == UiMode::Help {
        render_help_popup(f, app, full);
    }
    if app.pending_action.is_some() {
        render_action_confirm_popup(f, app, full);
        return;
    }
    if let Some(message) = &app.connection_error {
        render_connection_error_popup(f, message, full);
        return;
    }

    match app.active_session_state() {
        VpnState::WaitingToken => {
            render_token_popup(f, app, full);
        }
        VpnState::WaitingCert => {
            if let Some(cert) = app.active_session().and_then(|s| s.pending_cert.as_ref()) {
                render_cert_popup(f, app, cert, full);
            }
        }
        _ => {
            if let Some((msg, level)) = &app.notification {
                render_notification(f, msg, level, full);
            }
        }
    }
}

fn render_action_confirm_popup(f: &mut Frame, app: &App, area: Rect) {
    let Some(action) = app.pending_action.as_ref() else {
        return;
    };
    let popup_w = 60u16;
    let popup_h = 9u16;
    let popup_x = area.x + area.width.saturating_sub(popup_w) / 2;
    let popup_y = area.y + area.height.saturating_sub(popup_h) / 2;
    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", action.title()),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_YELLOW))
        .style(Style::default().bg(Color::Rgb(24, 20, 12)));
    f.render_widget(block, popup_area);

    let inner = Rect {
        x: popup_area.x + 2,
        y: popup_area.y + 1,
        width: popup_area.width.saturating_sub(4),
        height: popup_area.height.saturating_sub(2),
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    let target = match action {
        PendingAction::DisconnectActive | PendingAction::CloseActive => app
            .active_session()
            .map(|s| format!("Session '{}'", s.profile_name))
            .unwrap_or_else(|| "Session aktif".into()),
        PendingAction::DisconnectAll => format!("Semua session aktif ({})", app.sessions.len()),
        PendingAction::CloseAllIdle => "Semua tab session idle".into(),
    };

    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "Aksi berikut akan dijalankan:",
                Style::default().fg(C_TEXT),
            )),
            Line::from(Span::styled(
                target,
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )),
        ]),
        rows[0],
    );

    let btn_rows = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    let yes_focused = app.focus == Focus::ActionConfirmAccept;
    let no_focused = app.focus == Focus::ActionConfirmDeny;

    let yes_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if yes_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(C_GREEN));
    let no_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if no_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(C_RED));

    f.render_widget(
        Paragraph::new(" Ya [Y/Enter] ")
            .block(yes_block)
            .style(if yes_focused {
                Style::default()
                    .fg(C_BG)
                    .bg(C_GREEN)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)
            })
            .alignment(Alignment::Center),
        btn_rows[0],
    );
    f.render_widget(
        Paragraph::new(" Batal [N/Esc] ")
            .block(no_block)
            .style(if no_focused {
                Style::default()
                    .fg(C_BG)
                    .bg(C_RED)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
            })
            .alignment(Alignment::Center),
        btn_rows[1],
    );
}

// --- Title Bar ---------------------------------------------------------------
fn render_title(f: &mut Frame, app: &App, area: Rect) {
    let session_state = app.active_session_state();
    let state_color = match &session_state {
        VpnState::Disconnected => C_DIM,
        VpnState::Connecting => C_YELLOW,
        VpnState::WaitingToken => C_ORANGE,
        VpnState::WaitingCert => C_ORANGE,
        VpnState::Connected => C_GREEN,
        VpnState::Disconnecting => C_YELLOW,
        VpnState::Error(_) => C_RED,
    };

    let mode_indicator = match app.ui_mode {
        UiMode::ProfileList => " PROFILES",
        UiMode::NewProfile => " NEW PROFILE",
        UiMode::EditProfile => " EDIT PROFILE",
        UiMode::Connect => " CONNECT",
        UiMode::Help => " HELP",
    };

    let title_line = Line::from(vec![
        Span::styled(
            "  OPENFortiVPN  ",
            Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD),
        ),
        Span::styled("TUI   ", Style::default().fg(C_DIM)),
        Span::styled("|   ", Style::default().fg(C_BORDER)),
        Span::styled(
            format!("{}   ", mode_indicator),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled("|   ", Style::default().fg(C_BORDER)),
        Span::styled(
            format!("{}   ", app.active_session_label()),
            Style::default().fg(C_YELLOW),
        ),
        Span::styled("|   ", Style::default().fg(C_BORDER)),
        Span::styled(
            session_state.label(),
            Style::default()
                .fg(state_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_SURFACE));

    f.render_widget(Paragraph::new(title_line).block(block), area);
}

// --- Main Body ---------------------------------------------------------------
fn render_body(f: &mut Frame, app: &App, area: Rect) {
    match app.ui_mode {
        UiMode::ProfileList => {
            let panels = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(area);
            render_profile_list(f, app, panels[0]);
            render_profile_details(f, app, panels[1]);
        }
        UiMode::NewProfile | UiMode::EditProfile => {
            render_profile_form(f, app, area);
        }
        UiMode::Connect => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(10)])
                .split(area);
            render_session_tabs(f, app, rows[0]);
            render_connection_workspace(f, app, rows[1]);
        }
        UiMode::Help => {
            // Konten tetap dirender sesuai mode sebelumnya
            if let Some(ref mode) = app.previous_ui_mode {
                match mode {
                    UiMode::ProfileList => {
                        let panels = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                            .split(area);
                        render_profile_list(f, app, panels[0]);
                        render_profile_details(f, app, panels[1]);
                    }
                    UiMode::Connect => {
                        let rows = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([Constraint::Length(3), Constraint::Min(10)])
                            .split(area);
                        render_session_tabs(f, app, rows[0]);
                        render_connection_workspace(f, app, rows[1]);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn render_session_tabs(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Sessions ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_SURFACE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.sessions.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                "Belum ada session aktif",
                Style::default().fg(C_DIM),
            ))
            .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let mut spans = Vec::new();
    for (idx, session) in app.sessions.iter().enumerate() {
        let is_active = app.active_session_index == Some(idx);
        let style = if is_active {
            Style::default()
                .fg(C_BG)
                .bg(C_FOCUS)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_TEXT).bg(C_BG)
        };
        spans.push(Span::styled(
            format!(
                " {} {} ({}) ",
                idx + 1,
                session.profile_name,
                session.vpn_state.label()
            ),
            style,
        ));
        spans.push(Span::styled(" ", Style::default()));
    }

    f.render_widget(Paragraph::new(Line::from(spans)), inner);
}

// --- Help Popup --------------------------------------------------------------
fn render_help_popup(f: &mut Frame, _app: &App, area: Rect) {
    let popup_w = 72u16;
    let popup_h = 28u16;
    let popup_x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let popup_y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };

    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Help - Keyboard Shortcuts ",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_CYAN))
        .style(Style::default().bg(Color::Rgb(20, 20, 30)));

    f.render_widget(block, popup_area);

    let inner = Rect {
        x: popup_area.x + 2,
        y: popup_area.y + 1,
        width: popup_area.width.saturating_sub(4),
        height: popup_area.height.saturating_sub(2),
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(6),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(inner);

    let title_style = Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD);
    let key_style = Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD);
    let desc_style = Style::default().fg(C_TEXT);

    // Global Shortcuts
    f.render_widget(
        Paragraph::new(Span::styled(
            "======================= GLOBAL SHORTCUTS =======================",
            title_style,
        )),
        rows[1],
    );

    let global_shortcuts = [
        ("F1", "Buka help ini"),
        ("ESC / Ctrl+B", "Kembali ke daftar profile / Tutup help"),
        ("Ctrl+Q / Ctrl+C", "Keluar aplikasi"),
    ];

    let global_text: Vec<Line> = global_shortcuts
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("  {:<14}", key), key_style),
                Span::styled(format!("  {}", desc), desc_style),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(global_text), rows[2]);

    // Profile List Shortcuts
    f.render_widget(
        Paragraph::new(Span::styled(
            "======================= PROFILE LIST MODE =======================",
            title_style,
        )),
        rows[4],
    );

    let profile_shortcuts = [
        ("up / down", "Pilih profile"),
        ("Enter / F5", "Connect ke profile terpilih"),
        ("F2 / N", "Buat profile baru"),
        ("F3 / E", "Edit profile terpilih"),
        ("F4 / D", "Hapus profile terpilih (konfirmasi dua kali)"),
    ];

    let profile_text: Vec<Line> = profile_shortcuts
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("  {:<14}", key), key_style),
                Span::styled(format!("  {}", desc), desc_style),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(profile_text), rows[5]);

    // Connect Mode Shortcuts
    f.render_widget(
        Paragraph::new(Span::styled(
            "======================= CONNECT MODE =======================",
            title_style,
        )),
        rows[7],
    );

    let connect_shortcuts = vec![
        ("<- / ->", "Pindah session aktif"),
        ("Tab", "Pindah fokus Connect/Disconnect"),
        ("Shift+Tab", "Pindah fokus Connect/Disconnect"),
        ("Enter", "Connect / Disconnect"),
        ("Ctrl+K", "Disconnect session aktif"),
        ("Ctrl+Shift+K", "Disconnect semua session"),
        ("Ctrl+W", "Tutup tab session aktif"),
        ("Ctrl+Shift+W", "Tutup semua tab yang sudah idle"),
    ];

    let connect_text: Vec<Line> = connect_shortcuts
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(format!("  {:<14}", key), key_style),
                Span::styled(format!("  {}", desc), desc_style),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(connect_text), rows[8]);

    // Hint
    let hint_style = Style::default().fg(C_DIM);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "  Debug log: jalankan `openfortivpn-tui -d` untuk simpan log ke /tmp/openfortivpn-tui.log",
                hint_style,
            )),
            Line::from(Span::styled(
                "  Tekan ESC atau F1 untuk menutup help ini",
                hint_style,
            )),
        ])
            .alignment(Alignment::Center),
        rows[10],
    );
}

// --- Profile List ------------------------------------------------------------
fn render_profile_list(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title("  VPN Connections ")
        .title_style(Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_SURFACE));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.profiles.is_empty() {
        let empty_msg = Paragraph::new(Span::styled(
            "Belum ada koneksi.\n\nTekan [F2] atau [N] untuk membuat baru",
            Style::default().fg(C_DIM),
        ))
        .alignment(Alignment::Center);
        f.render_widget(empty_msg, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(i, profile)| {
            let is_selected = i == app.selected_profile_index;
            let is_focused = matches!(app.focus, Focus::ProfileItem(idx) if idx == i);
            let has_session = app.find_session_by_profile_name(&profile.name);

            let style = if is_focused {
                Style::default()
                    .fg(C_BG)
                    .bg(C_FOCUS)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_TEXT)
            };

            let mut spans = vec![
                Span::styled(profile.name.clone(), style),
                Span::styled(
                    format!(" {}:{}", profile.host, profile.port),
                    Style::default().fg(C_DIM),
                ),
                Span::styled(
                    if profile.trusted_cert.is_some() {
                        " trusted"
                    } else {
                        " untrusted"
                    },
                    if profile.trusted_cert.is_some() {
                        Style::default().fg(C_GREEN)
                    } else {
                        Style::default().fg(C_YELLOW)
                    },
                ),
            ];

            if let Some(session_idx) = has_session {
                spans.push(Span::styled(
                    format!(" [S{}]", session_idx + 1),
                    Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, inner);
}

// --- Profile Details ---------------------------------------------------------
fn render_profile_details(f: &mut Frame, app: &App, area: Rect) {
    if app.profiles.is_empty() {
        return;
    }

    if let Some(profile) = app.profiles.get(app.selected_profile_index) {
        let block = Block::default()
            .title("  Connection Details ")
            .title_style(Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_SURFACE));

        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Min(0),
            ])
            .split(inner);

        let label_style = Style::default().fg(C_DIM);
        let value_style = Style::default().fg(C_TEXT);

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Nama:     ", label_style),
                Span::styled(&profile.name, value_style.add_modifier(Modifier::BOLD)),
            ])),
            rows[0],
        );

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Host:     ", label_style),
                Span::styled(format!("{}:{}", profile.host, profile.port), value_style),
            ])),
            rows[1],
        );

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Username: ", label_style),
                Span::styled(&profile.username, value_style),
            ])),
            rows[2],
        );

        let cert_status = if profile.trusted_cert.is_some() {
            "Trusted"
        } else {
            "Not trusted"
        };
        let cert_color = if profile.trusted_cert.is_some() {
            C_GREEN
        } else {
            C_YELLOW
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Cert:     ", label_style),
                Span::styled(cert_status, Style::default().fg(cert_color)),
            ])),
            rows[3],
        );

        let password_status = if profile.save_password {
            "Saved"
        } else {
            "Not saved"
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Password: ", label_style),
                Span::styled(
                    password_status,
                    Style::default().fg(if profile.save_password {
                        C_GREEN
                    } else {
                        C_DIM
                    }),
                ),
            ])),
            rows[4],
        );

        let sudo_status = if profile.use_sudo_password {
            "Enabled"
        } else {
            "Disabled"
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Sudo:     ", label_style),
                Span::styled(
                    sudo_status,
                    Style::default().fg(if profile.use_sudo_password {
                        C_GREEN
                    } else {
                        C_DIM
                    }),
                ),
            ])),
            rows[5],
        );

        let btn_area = rows[6];
        let btn_rows = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(34),
                Constraint::Percentage(33),
            ])
            .split(btn_area);

        let connect_btn = Paragraph::new("  Connect ")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded),
            )
            .alignment(Alignment::Center);
        f.render_widget(connect_btn, btn_rows[0]);

        let edit_btn = Paragraph::new("  Edit ")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded),
            )
            .alignment(Alignment::Center);
        f.render_widget(edit_btn, btn_rows[1]);

        let delete_btn = Paragraph::new("  Delete ")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded),
            )
            .alignment(Alignment::Center);
        f.render_widget(delete_btn, btn_rows[2]);
    }
}

// --- Profile Form ------------------------------------------------------------
fn render_profile_form(f: &mut Frame, app: &App, area: Rect) {
    let title = match app.ui_mode {
        UiMode::NewProfile => "  New VPN Connection ",
        UiMode::EditProfile => "  Edit VPN Connection ",
        _ => " VPN Connection ",
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_FOCUS))
        .style(Style::default().bg(C_SURFACE));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    render_input(
        f,
        rows[0],
        " Profile Name ",
        &app.profile_name,
        matches!(app.focus, Focus::ProfileName),
        false,
        "My VPN",
    );
    render_input(
        f,
        rows[1],
        " Host ",
        &app.profile_host,
        matches!(app.focus, Focus::Host),
        false,
        "vpn.example.com",
    );
    render_input(
        f,
        rows[2],
        " Port ",
        &app.profile_port,
        matches!(app.focus, Focus::Port),
        false,
        "443",
    );
    render_input(
        f,
        rows[3],
        " Username ",
        &app.profile_username,
        matches!(app.focus, Focus::Username),
        false,
        "user@domain",
    );
    render_input(
        f,
        rows[4],
        " Password ",
        &app.profile_password,
        matches!(app.focus, Focus::Password),
        !app.show_password,
        "tersembunyi",
    );
    render_input(
        f,
        rows[5],
        " Sudo Password ",
        &app.profile_sudo_password,
        matches!(app.focus, Focus::SudoPassword),
        true,
        "kosongkan jika NOPASSWD",
    );

    let save_pwd_style = if matches!(app.focus, Focus::SavePassword) {
        Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };
    let save_pwd_check = if app.profile_save_password {
        "Aktif"
    } else {
        "Nonaktif"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            format!("Simpan password: {}", save_pwd_check),
            save_pwd_style,
        )])),
        rows[6],
    );

    let use_sudo_style = if matches!(app.focus, Focus::UseSudoPassword) {
        Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };
    let use_sudo_check = if app.profile_use_sudo_password {
        "Aktif"
    } else {
        "Nonaktif"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![Span::styled(
            format!("Gunakan sudo password: {}", use_sudo_check),
            use_sudo_style,
        )])),
        rows[7],
    );

    let btn_area = rows[8];
    let btn_rows = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(btn_area);

    let save_btn = Paragraph::new("  Save ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .alignment(Alignment::Center);
    let cancel_btn = Paragraph::new(" Cancel ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .alignment(Alignment::Center);

    f.render_widget(save_btn, btn_rows[0]);
    f.render_widget(cancel_btn, btn_rows[1]);
}

fn render_connection_workspace(f: &mut Frame, app: &App, area: Rect) {
    render_connection_dashboard(f, app, area);
}

fn render_connection_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let Some(session) = app.active_session() else {
        return;
    };

    let state = &session.vpn_state;
    let state_color = match state {
        VpnState::Disconnected => C_DIM,
        VpnState::Connecting => C_YELLOW,
        VpnState::WaitingToken | VpnState::WaitingCert => C_ORANGE,
        VpnState::Connected => C_GREEN,
        VpnState::Disconnecting => C_YELLOW,
        VpnState::Error(_) => C_RED,
    };
    let duration = session
        .connected_at
        .map(|started| format_duration(started.elapsed()))
        .unwrap_or_else(|| "-".into());
    let interface = session.vpn_interface.as_deref().unwrap_or("-");
    let pid = session
        .vpn_pid
        .lock()
        .unwrap()
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".into());

    let block = Block::default()
        .title(Span::styled(
            " Connection Dashboard ",
            Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_SURFACE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    let label = Style::default().fg(C_DIM);
    let value = Style::default().fg(C_TEXT);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Profile  ", label),
            Span::styled(
                &session.profile_name,
                Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD),
            ),
        ])),
        rows[0],
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Status  ", label),
            Span::styled(
                state.label().to_string(),
                Style::default()
                    .fg(state_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Duration  ", label),
            Span::styled(duration, value),
        ])),
        rows[1],
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Interface  ", label),
            Span::styled(
                interface,
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   PID  ", label),
            Span::styled(pid, value),
        ])),
        rows[2],
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Speed  ", label),
            Span::styled(
                format!("down {}/s", format_bytes(session.rx_speed_bps)),
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   ", label),
            Span::styled(
                format!("up {}/s", format_bytes(session.tx_speed_bps)),
                Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
            ),
        ])),
        rows[3],
    );

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Total  ", label),
            Span::styled(
                format!("down {}", format_bytes(session.rx_total_bytes)),
                Style::default().fg(C_GREEN),
            ),
            Span::styled("   ", label),
            Span::styled(
                format!("up {}", format_bytes(session.tx_total_bytes)),
                Style::default().fg(C_YELLOW),
            ),
        ])),
        rows[4],
    );

    render_dashboard_actions(f, app, rows[6], rows[7]);
}

fn render_dashboard_actions(f: &mut Frame, app: &App, connect_area: Rect, disconnect_area: Rect) {
    let Some(session) = app.active_session() else {
        return;
    };

    let can_connect = matches!(
        session.vpn_state,
        VpnState::Disconnected | VpnState::Error(_)
    );
    let conn_focused = app.focus == Focus::Connect;
    let conn_style = match (can_connect, conn_focused) {
        (true, true) => Style::default()
            .fg(C_BG)
            .bg(C_GREEN)
            .add_modifier(Modifier::BOLD),
        (true, false) => Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(C_DIM),
    };

    let connect_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if conn_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(if conn_focused { C_GREEN } else { C_BORDER }));

    f.render_widget(
        Paragraph::new(if conn_focused {
            " CONNECT [Enter] "
        } else {
            " CONNECT "
        })
        .block(connect_block)
        .style(conn_style)
        .alignment(Alignment::Center),
        connect_area,
    );

    let can_disconn = matches!(
        session.vpn_state,
        VpnState::Connected | VpnState::Connecting | VpnState::WaitingToken | VpnState::WaitingCert
    );
    let disc_focused = app.focus == Focus::Disconnect;
    let disc_style = match (can_disconn, disc_focused) {
        (true, true) => Style::default()
            .fg(C_BG)
            .bg(C_RED)
            .add_modifier(Modifier::BOLD),
        (true, false) => Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
        _ => Style::default().fg(C_DIM),
    };

    let disconnect_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if disc_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(if disc_focused { C_RED } else { C_BORDER }));

    f.render_widget(
        Paragraph::new(if disc_focused {
            " DISCONNECT [Enter] "
        } else {
            " DISCONNECT "
        })
        .block(disconnect_block)
        .style(disc_style)
        .alignment(Alignment::Center),
        disconnect_area,
    );
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}", minutes, seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut value = bytes as f64;
    let mut unit = UNITS[0];

    for next_unit in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next_unit;
    }

    if unit == "B" {
        format!("{} {}", bytes, unit)
    } else {
        format!("{:.1} {}", value, unit)
    }
}

// --- Input Widget -------------------------------------------------------------
fn render_input(
    f: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
    masked: bool,
    placeholder: &str,
) {
    let border_style = if focused {
        Style::default().fg(C_FOCUS)
    } else {
        Style::default().fg(C_BORDER)
    };
    let border_type = if focused {
        BorderType::Thick
    } else {
        BorderType::Rounded
    };

    let label_style = if focused {
        Style::default().fg(C_FOCUS).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_DIM)
    };

    let block = Block::default()
        .title(Span::styled(label, label_style))
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .padding(Padding::horizontal(1));

    let display = if value.is_empty() {
        Span::styled(placeholder, Style::default().fg(C_DIM))
    } else if masked {
        Span::styled("tersembunyi", Style::default().fg(C_TEXT))
    } else {
        Span::styled(value, Style::default().fg(C_TEXT))
    };

    let content = if focused && !value.is_empty() {
        Line::from(vec![Span::styled(
            if masked {
                "tersembunyi".to_string()
            } else {
                value.to_string()
            },
            Style::default().fg(C_TEXT),
        )])
    } else if focused && value.is_empty() {
        Line::from(Span::styled(placeholder, Style::default().fg(C_DIM)))
    } else {
        Line::from(display)
    };

    f.render_widget(Paragraph::new(content).block(block), area);
}

// --- Status / Hint Bar -------------------------------------------------------
fn render_statusbar(f: &mut Frame, app: &App, area: Rect) {
    if app.ui_mode == UiMode::Help {
        let hints = [("ESC / F1", "Tutup Help")];

        let mut spans = vec![Span::styled("  ", Style::default())];
        for (i, (key, desc)) in hints.iter().enumerate() {
            spans.push(Span::styled(
                format!("[{}]", key),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(" {} ", desc),
                Style::default().fg(C_DIM),
            ));
            if i < hints.len() - 1 {
                spans.push(Span::styled(" | ", Style::default().fg(C_BORDER)));
            }
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_SURFACE));

        f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
        return;
    }

    let hints = match app.ui_mode {
        UiMode::ProfileList => vec![
            ("up/down", "Pilih"),
            ("Enter/F5", "Connect"),
            ("F2/N", "New"),
            ("F3/E", "Edit"),
            ("F4/D", "Delete"),
            ("ESC/Ctrl+B", "Back"),
            ("F1", "Help"),
            ("Ctrl+Q", "Quit"),
        ],
        UiMode::NewProfile | UiMode::EditProfile => vec![
            ("Tab", "Next"),
            ("Shift+Tab", "Prev"),
            ("Space", "Toggle"),
            ("Enter", "Save"),
            ("ESC/Ctrl+B", "Cancel"),
            ("F1", "Help"),
        ],
        UiMode::Connect => vec![
            ("<-/->", "Tab"),
            ("Tab", "Focus"),
            ("Enter", "Action"),
            ("Ctrl+K", "Disc 1"),
            ("Ctrl+Shift+K", "Disc all"),
            ("Ctrl+W", "Close"),
            ("Ctrl+Shift+W", "Close idle"),
            ("ESC/Ctrl+B", "Back"),
            ("F1", "Help"),
            ("Ctrl+Q", "Quit"),
        ],
        UiMode::Help => vec![],
    };

    let mut spans = vec![Span::styled("  ", Style::default())];
    for (i, (key, desc)) in hints.iter().enumerate() {
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!("{} ", desc),
            Style::default().fg(C_DIM),
        ));
        if i < hints.len() - 1 {
            spans.push(Span::styled("| ", Style::default().fg(C_BORDER)));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_SURFACE));

    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

// --- Floating Notification ---------------------------------------------------
fn render_notification(f: &mut Frame, msg: &str, level: &NotifLevel, area: Rect) {
    let (bg, fg) = match level {
        NotifLevel::Info => (Color::Rgb(30, 50, 80), C_FOCUS),
        NotifLevel::Success => (Color::Rgb(20, 60, 30), C_GREEN),
        NotifLevel::Warning => (Color::Rgb(70, 55, 10), C_YELLOW),
        NotifLevel::Error => (Color::Rgb(70, 20, 20), C_RED),
    };
    let width = (msg.len() as u16 + 8).min(area.width - 4).max(20);
    let height = 3u16;
    let x = area.x + (area.width - width) / 2;
    let y = area.y + 1;

    let notif_area = Rect {
        x,
        y,
        width,
        height,
    };
    f.render_widget(Clear, notif_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(fg))
        .style(Style::default().bg(bg));

    f.render_widget(
        Paragraph::new(Span::styled(
            msg,
            Style::default().fg(fg).add_modifier(Modifier::BOLD),
        ))
        .block(block)
        .alignment(Alignment::Center),
        notif_area,
    );
}

fn render_connection_error_popup(f: &mut Frame, message: &str, area: Rect) {
    let popup_w = (area.width.saturating_sub(4)).min(64).max(36);
    let popup_h = 9u16.min(area.height.saturating_sub(2)).max(7);
    let popup_x = area.x + area.width.saturating_sub(popup_w) / 2;
    let popup_y = area.y + area.height.saturating_sub(popup_h) / 2;
    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Gagal Koneksi ",
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_RED))
        .padding(Padding::uniform(1))
        .style(Style::default().bg(C_SURFACE));

    let content = vec![
        Line::from(Span::styled(
            message,
            Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Tekan Enter atau Esc untuk kembali.",
            Style::default().fg(C_DIM),
        )),
    ];

    f.render_widget(
        Paragraph::new(content)
            .block(block)
            .alignment(Alignment::Center),
        popup_area,
    );
}

// --- Certificate Approval Popup -----------------------------------------------
fn render_cert_popup(f: &mut Frame, app: &App, cert: &crate::app::CertInfo, area: Rect) {
    let popup_w = (area.width as f32 * 0.72) as u16;
    let popup_h = 18u16;
    let popup_x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let popup_y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Certificate Tidak Dipercaya ",
            Style::default()
                .fg(Color::Rgb(255, 200, 50))
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(Color::Rgb(255, 200, 50)))
        .style(Style::default().bg(Color::Rgb(20, 18, 10)));
    f.render_widget(block, popup_area);

    let inner = Rect {
        x: popup_area.x + 2,
        y: popup_area.y + 1,
        width: popup_area.width.saturating_sub(4),
        height: popup_area.height.saturating_sub(2),
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Gateway VPN menggunakan certificate yang tidak ada di whitelist:",
            Style::default().fg(Color::Rgb(220, 200, 140)),
        )),
        rows[0],
    );

    let detail_style = Style::default().fg(Color::Rgb(180, 220, 255));
    let label_style = Style::default().fg(Color::Rgb(100, 160, 220));

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Subject CN  :  ", label_style),
            Span::styled(&cert.subject_cn, detail_style.add_modifier(Modifier::BOLD)),
        ])),
        rows[2],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Org         :  ", label_style),
            Span::styled(&cert.subject_org, detail_style),
        ])),
        rows[3],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Issuer CN   :  ", label_style),
            Span::styled(&cert.issuer_cn, detail_style),
        ])),
        rows[4],
    );

    f.render_widget(
        Paragraph::new(Span::styled("  SHA256 Digest: ", label_style)),
        rows[6],
    );

    let hash_display = if cert.hash.len() > (inner.width as usize).saturating_sub(4) {
        format!(
            "  {}... ",
            &cert.hash[..inner.width.saturating_sub(8) as usize]
        )
    } else {
        format!("  {} ", cert.hash)
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            hash_display,
            Style::default()
                .fg(Color::Rgb(255, 220, 80))
                .add_modifier(Modifier::BOLD),
        )),
        rows[7],
    );

    f.render_widget(
        Paragraph::new(Span::styled(
            "Apakah Anda mempercayai certificate ini?",
            Style::default()
                .fg(Color::Rgb(220, 220, 220))
                .add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        rows[9],
    );

    let btn_area = rows[11];
    let btn_rows = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(btn_area);

    let accept_focused = app.focus == Focus::CertAccept;
    let deny_focused = app.focus == Focus::CertDeny;

    let accept_style = if accept_focused {
        Style::default()
            .fg(Color::Rgb(20, 20, 20))
            .bg(Color::Rgb(80, 220, 120))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Rgb(80, 220, 120))
            .add_modifier(Modifier::BOLD)
    };
    let accept_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if accept_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(Color::Rgb(80, 220, 120)));

    f.render_widget(
        Paragraph::new(" Percaya dan connect [Y/Enter] ")
            .block(accept_block)
            .style(accept_style)
            .alignment(Alignment::Center),
        btn_rows[0],
    );

    let deny_style = if deny_focused {
        Style::default()
            .fg(Color::Rgb(20, 20, 20))
            .bg(Color::Rgb(255, 80, 80))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Rgb(255, 80, 80))
            .add_modifier(Modifier::BOLD)
    };
    let deny_block = Block::default()
        .borders(Borders::ALL)
        .border_type(if deny_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(Color::Rgb(255, 80, 80)));

    f.render_widget(
        Paragraph::new(" Tolak [N/Esc] ")
            .block(deny_block)
            .style(deny_style)
            .alignment(Alignment::Center),
        btn_rows[1],
    );

    let hint_area = Rect {
        x: popup_area.x + 2,
        y: popup_area.y + popup_area.height - 1,
        width: popup_area.width.saturating_sub(4),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "[Tab/<-/->] ",
                Style::default()
                    .fg(Color::Rgb(60, 210, 210))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("pindah    ", Style::default().fg(Color::Rgb(80, 80, 100))),
            Span::styled(
                "[Y] ",
                Style::default()
                    .fg(Color::Rgb(60, 210, 210))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("accept    ", Style::default().fg(Color::Rgb(80, 80, 100))),
            Span::styled(
                "[N/Esc] ",
                Style::default()
                    .fg(Color::Rgb(60, 210, 210))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("tolak   ", Style::default().fg(Color::Rgb(80, 80, 100))),
        ])),
        hint_area,
    );
}

// --- Token Input Popup --------------------------------------------------------
fn render_token_popup(f: &mut Frame, app: &App, area: Rect) {
    let Some(session) = app.active_session() else {
        return;
    };
    let popup_w = 52u16;
    let popup_h = 11u16;
    let popup_x = area.x + area.width.saturating_sub(popup_w) / 2;
    let popup_y = area.y + area.height.saturating_sub(popup_h) / 2;
    let popup_area = Rect {
        x: popup_x,
        y: popup_y,
        width: popup_w,
        height: popup_h,
    };
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Span::styled(
            " Two-Factor Authentication ",
            Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_ORANGE))
        .style(Style::default().bg(Color::Rgb(20, 14, 5)));
    f.render_widget(block, popup_area);

    let inner = Rect {
        x: popup_area.x + 2,
        y: popup_area.y + 1,
        width: popup_area.width.saturating_sub(4),
        height: popup_area.height.saturating_sub(2),
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(Span::styled(
            "Masukkan OTP token yang dikirim ke email/app Anda:",
            Style::default().fg(Color::Rgb(220, 200, 140)),
        )),
        rows[0],
    );

    let token_display = &session.token_input;
    let input_content = if token_display.is_empty() {
        Line::from(vec![
            Span::styled("   ", Style::default()),
            Span::styled("Ketik token di sini... ", Style::default().fg(C_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("   ", Style::default()),
            Span::styled(
                token_display.as_str(),
                Style::default()
                    .fg(Color::Rgb(255, 230, 80))
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    };

    let input_block = Block::default()
        .title(Span::styled(" OTP Token  ", Style::default().fg(C_ORANGE)))
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_ORANGE));

    f.render_widget(Paragraph::new(input_content).block(input_block), rows[2]);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "[Enter] ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("submit    ", Style::default().fg(C_DIM)),
            Span::styled(
                "[Backspace] ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("hapus    ", Style::default().fg(C_DIM)),
            Span::styled(
                "[Esc] ",
                Style::default()
                    .fg(Color::Rgb(255, 120, 80))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("batalkan ", Style::default().fg(C_DIM)),
        ]))
        .alignment(Alignment::Center),
        rows[4],
    );
}
