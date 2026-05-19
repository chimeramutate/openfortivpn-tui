use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    process::ChildStdin,
    sync::{Mutex as AsyncMutex, mpsc},
};

// --- VPN Connection State -----------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum VpnState {
    Disconnected,
    Connecting,
    WaitingCert,
    WaitingToken,
    Connected,
    Disconnecting,
    Error(String),
}

impl VpnState {
    pub fn label(&self) -> &str {
        match self {
            VpnState::Disconnected => "DISCONNECTED",
            VpnState::Connecting => "CONNECTING...",
            VpnState::WaitingCert => "CERT UNTRUSTED",
            VpnState::WaitingToken => "WAITING TOKEN",
            VpnState::Connected => "CONNECTED",
            VpnState::Disconnecting => "DISCONNECTING...",
            VpnState::Error(_) => "ERROR",
        }
    }
}

// --- Certificate Info ---------------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct CertInfo {
    pub hash: String,
    pub subject_cn: String,
    pub subject_org: String,
    pub issuer_cn: String,
}

// --- UI Mode -----------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum UiMode {
    ProfileList,
    NewProfile,
    EditProfile,
    Connect,
    Help,
}

// --- Focus Tracking -----------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    // Profile list mode
    ProfileList,
    ProfileItem(usize),

    // Form mode
    ProfileName,
    Host,
    Port,
    Username,
    Password,
    SudoPassword,
    SavePassword,
    UseSudoPassword,

    // Action buttons
    Connect,
    Disconnect,

    // Modal dialogs
    CertAccept,
    CertDeny,
    ActionConfirmAccept,
    ActionConfirmDeny,
    TokenInput,
    HelpPopup,
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    DisconnectActive,
    DisconnectAll,
    CloseActive,
    CloseAllIdle,
}

impl PendingAction {
    pub fn title(&self) -> &'static str {
        match self {
            PendingAction::DisconnectActive => "DISCONNECT SESSION",
            PendingAction::DisconnectAll => "DISCONNECT ALL SESSIONS",
            PendingAction::CloseActive => "CLOSE SESSION TAB",
            PendingAction::CloseAllIdle => "CLOSE IDLE TABS",
        }
    }
}

// --- Events -------------------------------------------------------------------
#[derive(Debug)]
pub enum AppEvent {
    LogLine {
        session_id: u64,
        line: String,
    },
    DebugLog(String),
    StateChanged {
        session_id: u64,
        state: VpnState,
    },
    SpeedUpdate {
        session_id: u64,
        interface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_total: u64,
        tx_total: u64,
    },
    NeedToken(u64),
    CertError {
        session_id: u64,
        cert: CertInfo,
    },
}

pub struct ConnectionSession {
    pub id: u64,
    pub profile_name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub sudo_password: String,
    pub token_input: String,
    pub vpn_state: VpnState,
    pub logs: Vec<String>,
    pub log_scroll: usize,
    pub pending_cert: Option<CertInfo>,
    pub trusted_cert: Option<String>,
    pub connected_at: Option<Instant>,
    pub vpn_interface: Option<String>,
    pub rx_speed_bps: u64,
    pub tx_speed_bps: u64,
    pub rx_total_bytes: u64,
    pub tx_total_bytes: u64,
    pub vpn_pid: Arc<Mutex<Option<u32>>>,
    pub vpn_stdin: Arc<AsyncMutex<Option<ChildStdin>>>,
    pub waiting_for_input_flag: Arc<Mutex<bool>>,
}

impl ConnectionSession {
    pub fn new(id: u64, profile: &crate::config::VpnProfile) -> Self {
        Self {
            id,
            profile_name: profile.name.clone(),
            host: profile.host.clone(),
            port: profile.port,
            username: profile.username.clone(),
            password: profile.password.clone(),
            sudo_password: profile.sudo_password.clone(),
            token_input: String::new(),
            vpn_state: VpnState::Disconnected,
            logs: Vec::new(),
            log_scroll: 0,
            pending_cert: None,
            trusted_cert: profile.trusted_cert.clone(),
            connected_at: None,
            vpn_interface: None,
            rx_speed_bps: 0,
            tx_speed_bps: 0,
            rx_total_bytes: 0,
            tx_total_bytes: 0,
            vpn_pid: Arc::new(Mutex::new(None)),
            vpn_stdin: Arc::new(AsyncMutex::new(None)),
            waiting_for_input_flag: Arc::new(Mutex::new(false)),
        }
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        let line = line.into();
        self.logs.push(line);
        if !self.logs.is_empty() {
            self.log_scroll = self.logs.len().saturating_sub(1);
        }
    }

    pub fn reset_connection_metrics(&mut self) {
        self.connected_at = None;
        self.vpn_interface = None;
        self.rx_speed_bps = 0;
        self.tx_speed_bps = 0;
        self.rx_total_bytes = 0;
        self.tx_total_bytes = 0;
    }
}

// --- App State ----------------------------------------------------------------
pub struct App {
    // UI state
    pub ui_mode: UiMode,
    pub previous_ui_mode: Option<UiMode>,
    pub focus: Focus,
    pub show_password: bool,
    pub logs: Vec<String>,
    pub log_scroll: usize,
    pub notification: Option<(String, NotifLevel)>,
    pub notification_ttl: u8,
    pub connection_error: Option<String>,
    pub pending_action: Option<PendingAction>,
    pub sessions: Vec<ConnectionSession>,
    pub active_session_index: Option<usize>,
    pub next_session_id: u64,

    // Profile management
    pub profiles: Vec<crate::config::VpnProfile>,
    pub selected_profile_index: usize,
    pub delete_confirmation: Option<String>,

    // Form for new/edit profile
    pub profile_name: String,
    pub profile_host: String,
    pub profile_port: String,
    pub profile_username: String,
    pub profile_password: String,
    pub profile_sudo_password: String,
    pub profile_save_password: bool,
    pub profile_use_sudo_password: bool,
    pub editing_profile_name: Option<String>,

    // Channel
    pub event_tx: mpsc::UnboundedSender<AppEvent>,
    pub event_rx: mpsc::UnboundedReceiver<AppEvent>,
    pub debug_enabled: bool,

    pub should_quit: bool,
}

#[derive(Debug, Clone)]
pub enum NotifLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl App {
    pub fn new(debug_enabled: bool) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            ui_mode: UiMode::ProfileList,
            previous_ui_mode: None,
            focus: Focus::ProfileList,
            show_password: false,
            logs: Vec::new(),
            log_scroll: 0,
            notification: None,
            notification_ttl: 0,
            connection_error: None,
            pending_action: None,
            sessions: Vec::new(),
            active_session_index: None,
            next_session_id: 1,
            profiles: Vec::new(),
            selected_profile_index: 0,
            delete_confirmation: None,
            profile_name: String::new(),
            profile_host: String::new(),
            profile_port: String::from("443"),
            profile_username: String::new(),
            profile_password: String::new(),
            profile_sudo_password: String::new(),
            profile_save_password: false,
            profile_use_sudo_password: false,
            editing_profile_name: None,
            event_tx,
            event_rx,
            debug_enabled,
            should_quit: false,
        }
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        let line = line.into();
        tracing::info!("{}", line);
        if let Some(session) = self.active_session_mut() {
            session.push_log(line);
        } else {
            self.logs.push(line);
            if !self.logs.is_empty() {
                self.log_scroll = self.logs.len().saturating_sub(1);
            }
        }
    }

    pub fn push_debug_log(&self, line: impl Into<String>) {
        if self.debug_enabled {
            tracing::info!("{}", line.into());
        }
    }

    pub fn notify(&mut self, msg: impl Into<String>, level: NotifLevel) {
        self.notification = Some((msg.into(), level));
        self.notification_ttl = 60;
    }

    pub fn show_connection_error(&mut self, msg: impl Into<String>) {
        self.connection_error = Some(msg.into());
    }

    pub fn clear_connection_error(&mut self) {
        self.connection_error = None;
        self.focus = Focus::Connect;
    }

    pub fn tick_notification(&mut self) {
        if self.notification_ttl > 0 {
            self.notification_ttl -= 1;
            if self.notification_ttl == 0 {
                self.notification = None;
            }
        }
    }

    pub fn has_modal(&self) -> bool {
        matches!(
            self.active_session_state(),
            VpnState::WaitingToken | VpnState::WaitingCert
        ) || self.ui_mode == UiMode::Help
            || self.connection_error.is_some()
            || self.pending_action.is_some()
    }

    pub fn request_action_confirmation(&mut self, action: PendingAction) {
        self.pending_action = Some(action);
        self.focus = Focus::ActionConfirmAccept;
    }

    pub fn clear_action_confirmation(&mut self) {
        self.pending_action = None;
        self.focus = Focus::Connect;
    }

    pub fn active_session(&self) -> Option<&ConnectionSession> {
        self.active_session_index
            .and_then(|idx| self.sessions.get(idx))
    }

    pub fn active_session_mut(&mut self) -> Option<&mut ConnectionSession> {
        self.active_session_index
            .and_then(move |idx| self.sessions.get_mut(idx))
    }

    pub fn active_session_state(&self) -> VpnState {
        self.active_session()
            .map(|s| s.vpn_state.clone())
            .unwrap_or(VpnState::Disconnected)
    }

    pub fn active_session_label(&self) -> String {
        self.active_session()
            .map(|s| s.profile_name.clone())
            .unwrap_or_else(|| "NO SESSION".into())
    }

    pub fn find_session_index_by_id(&self, session_id: u64) -> Option<usize> {
        self.sessions.iter().position(|s| s.id == session_id)
    }

    pub fn find_session_by_profile_name(&self, profile_name: &str) -> Option<usize> {
        self.sessions
            .iter()
            .position(|s| s.profile_name == profile_name)
    }

    pub fn activate_session(&mut self, index: usize) {
        if index < self.sessions.len() {
            self.active_session_index = Some(index);
            self.ui_mode = UiMode::Connect;
            self.focus = Focus::Connect;
        }
    }

    pub fn activate_next_session(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let next = match self.active_session_index {
            Some(idx) => (idx + 1) % self.sessions.len(),
            None => 0,
        };
        self.activate_session(next);
    }

    pub fn activate_prev_session(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let prev = match self.active_session_index {
            Some(0) | None => self.sessions.len() - 1,
            Some(idx) => idx.saturating_sub(1),
        };
        self.activate_session(prev);
    }

    pub fn ensure_session_for_selected_profile(&mut self) -> Option<u64> {
        let profile = self.get_current_profile()?.clone();
        if let Some(idx) = self.find_session_by_profile_name(&profile.name) {
            self.activate_session(idx);
            return self.sessions.get(idx).map(|s| s.id);
        }

        let session_id = self.next_session_id;
        self.next_session_id += 1;
        self.sessions
            .push(ConnectionSession::new(session_id, &profile));
        let idx = self.sessions.len().saturating_sub(1);
        self.activate_session(idx);
        Some(session_id)
    }

    pub fn close_active_session(&mut self) {
        let Some(idx) = self.active_session_index else {
            return;
        };
        self.sessions.remove(idx);
        if self.sessions.is_empty() {
            self.active_session_index = None;
            self.ui_mode = UiMode::ProfileList;
            self.focus = Focus::ProfileList;
        } else {
            let new_idx = idx.min(self.sessions.len().saturating_sub(1));
            self.activate_session(new_idx);
        }
    }

    pub fn cycle_focus_forward(&mut self) {
        if self.active_session_state() == VpnState::WaitingCert {
            self.focus = match self.focus {
                Focus::CertAccept => Focus::CertDeny,
                _ => Focus::CertAccept,
            };
            return;
        }
        if self.pending_action.is_some() {
            self.focus = match self.focus {
                Focus::ActionConfirmAccept => Focus::ActionConfirmDeny,
                _ => Focus::ActionConfirmAccept,
            };
            return;
        }
        if self.active_session_state() == VpnState::WaitingToken {
            return;
        }

        if self.ui_mode == UiMode::Connect {
            self.focus = match self.focus {
                Focus::Connect => Focus::Disconnect,
                Focus::Disconnect => Focus::Connect,
                _ => Focus::Connect,
            };
        }
    }

    pub fn cycle_focus_backward(&mut self) {
        if self.active_session_state() == VpnState::WaitingCert {
            self.focus = match self.focus {
                Focus::CertDeny => Focus::CertAccept,
                _ => Focus::CertDeny,
            };
            return;
        }
        if self.pending_action.is_some() {
            self.focus = match self.focus {
                Focus::ActionConfirmDeny => Focus::ActionConfirmAccept,
                _ => Focus::ActionConfirmDeny,
            };
            return;
        }
        if self.active_session_state() == VpnState::WaitingToken {
            return;
        }

        if self.ui_mode == UiMode::Connect {
            self.focus = match self.focus {
                Focus::Connect => Focus::Disconnect,
                Focus::Disconnect => Focus::Connect,
                _ => Focus::Connect,
            };
        }
    }

    pub fn show_help(&mut self) {
        if self.ui_mode != UiMode::Help {
            self.previous_ui_mode = Some(self.ui_mode.clone());
            self.ui_mode = UiMode::Help;
            self.focus = Focus::HelpPopup;
        }
    }

    pub fn hide_help(&mut self) {
        if let Some(prev_mode) = self.previous_ui_mode.take() {
            self.ui_mode = prev_mode;
            self.focus = Focus::ProfileList;
        } else {
            self.ui_mode = UiMode::ProfileList;
            self.focus = Focus::ProfileList;
        }
    }

    pub fn load_profiles(&mut self, profiles: Vec<crate::config::VpnProfile>) {
        self.profiles = profiles;
    }

    pub fn select_profile(&mut self, index: usize) {
        if index < self.profiles.len() {
            self.selected_profile_index = index;
            self.focus = Focus::ProfileItem(index);
        }
    }

    pub fn get_current_profile(&self) -> Option<&crate::config::VpnProfile> {
        self.profiles.get(self.selected_profile_index)
    }

    pub fn apply_current_profile(&mut self) {
        let _ = self.ensure_session_for_selected_profile();
    }

    pub fn update_profile_trusted_cert(&mut self, profile_name: &str, cert_hash: &str) {
        for profile in self.profiles.iter_mut() {
            if profile.name == profile_name {
                profile.trusted_cert = Some(cert_hash.to_string());
                break;
            }
        }
        for session in self.sessions.iter_mut() {
            if session.profile_name == profile_name {
                session.trusted_cert = Some(cert_hash.to_string());
            }
        }
    }

    pub fn back_to_profile_list(&mut self) {
        if self.ui_mode == UiMode::Connect && !self.has_modal() {
            self.ui_mode = UiMode::ProfileList;
            self.focus = Focus::ProfileList;
            self.push_log("[APP] Kembali ke daftar profile");
        } else if self.ui_mode == UiMode::NewProfile || self.ui_mode == UiMode::EditProfile {
            self.ui_mode = UiMode::ProfileList;
            self.focus = Focus::ProfileList;
            self.delete_confirmation = None;
            self.push_log("[APP] Kembali ke daftar profile");
        }
    }
}
