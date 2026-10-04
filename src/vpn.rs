use crate::app::{AppEvent, CertInfo, VpnState};
use anyhow::{Result, bail};
use libc::{ESRCH, SIGKILL, SIGTERM, c_int, kill};
use std::{
    collections::{HashMap, VecDeque},
    env,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::{Mutex as AsyncMutex, mpsc},
    time::Duration,
};

// --- Privilege Detection ------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub enum PrivilegeMethod {
    AlreadyRoot,
    SudoNoPassword,
    SudoWithPassword,
    Unavailable,
}

#[derive(Debug, Clone)]
enum RouteTarget {
    Host(Ipv4Addr),
    Network { addr: Ipv4Addr, prefix: u8 },
}

impl RouteTarget {
    fn display(&self) -> String {
        match self {
            RouteTarget::Host(addr) => addr.to_string(),
            RouteTarget::Network { addr, prefix } => format!("{addr}/{prefix}"),
        }
    }

    fn route_get_target(&self) -> String {
        match self {
            RouteTarget::Host(addr) => addr.to_string(),
            RouteTarget::Network { addr, .. } => addr.to_string(),
        }
    }
}

pub fn validate_route_targets(input: &str) -> Result<()> {
    let _ = parse_route_targets(input)?;
    Ok(())
}

fn parse_route_targets(input: &str) -> Result<Vec<RouteTarget>> {
    let mut targets = Vec::new();

    for raw in input.split([',', '\n']) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }

        if let Some((ip, prefix)) = raw.split_once('/') {
            let addr: Ipv4Addr = ip
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("CIDR tidak valid: {}", raw))?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Prefix CIDR tidak valid: {}", raw))?;
            if prefix > 32 {
                bail!("Prefix CIDR harus 0-32: {}", raw);
            }
            if prefix == 32 {
                targets.push(RouteTarget::Host(addr));
            } else {
                targets.push(RouteTarget::Network { addr, prefix });
            }
            continue;
        }

        let addr: Ipv4Addr = raw
            .parse()
            .map_err(|_| anyhow::anyhow!("IP target tidak valid: {}", raw))?;
        targets.push(RouteTarget::Host(addr));
    }

    Ok(targets)
}

impl PrivilegeMethod {
    pub fn label(&self) -> &str {
        match self {
            PrivilegeMethod::AlreadyRoot => "root (langsung)",
            PrivilegeMethod::SudoNoPassword => "sudo NOPASSWD",
            PrivilegeMethod::SudoWithPassword => "sudo -S (dengan password)",
            PrivilegeMethod::Unavailable => "tidak tersedia",
        }
    }
}

async fn detect_privilege_for_binary(
    binary_path: &str,
    tx: &mpsc::UnboundedSender<AppEvent>,
) -> PrivilegeMethod {
    if get_uid() == 0 {
        let _ = tx.send(AppEvent::DebugLog("[PRIV] Berjalan sebagai root".into()));
        return PrivilegeMethod::AlreadyRoot;
    }

    let sudo_nopass = Command::new("sudo")
        .args(["-n", binary_path, "--help"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if sudo_nopass {
        let _ = tx.send(AppEvent::DebugLog(format!(
            "[PRIV] sudo NOPASSWD tersedia untuk {}",
            binary_path
        )));
        return PrivilegeMethod::SudoNoPassword;
    }

    let has_sudo = Command::new("sudo")
        .arg("-V")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_sudo {
        let _ = tx.send(AppEvent::DebugLog(
            "[PRIV] sudo tersedia (butuh password)".into(),
        ));
        return PrivilegeMethod::SudoWithPassword;
    }

    let _ = tx.send(AppEvent::DebugLog(
        "[PRIV] Tidak ada metode privilege.".into(),
    ));
    PrivilegeMethod::Unavailable
}

unsafe extern "C" {
    fn getuid() -> u32;
}

fn get_uid() -> u32 {
    unsafe { getuid() }
}

fn send_signal(pid: u32, signal: c_int) -> bool {
    unsafe { kill(pid as i32, signal) == 0 }
}

fn process_exists(pid: u32) -> bool {
    let result = unsafe { kill(pid as i32, 0) };
    if result == 0 {
        return true;
    }

    std::io::Error::last_os_error()
        .raw_os_error()
        .is_some_and(|code| code != ESRCH)
}

fn find_in_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;

    env::split_paths(&path_var)
        .map(|dir| dir.join(binary_name))
        .find(|candidate| candidate.is_file())
}

fn resolve_openfortivpn_path() -> Option<PathBuf> {
    const COMMON_PATHS: [&str; 4] = [
        "/opt/homebrew/bin/openfortivpn",
        "/usr/local/bin/openfortivpn",
        "/usr/bin/openfortivpn",
        "/usr/sbin/openfortivpn",
    ];

    COMMON_PATHS
        .iter()
        .map(Path::new)
        .find(|candidate| candidate.is_file())
        .map(Path::to_path_buf)
        .or_else(|| find_in_path("openfortivpn"))
}

fn detect_install_hint() -> Option<&'static str> {
    [
        (
            "apt",
            "Install contoh: sudo apt update && sudo apt install openfortivpn",
        ),
        ("dnf", "Install contoh: sudo dnf install openfortivpn"),
        ("pacman", "Install contoh: sudo pacman -S openfortivpn"),
        ("zypper", "Install contoh: sudo zypper install openfortivpn"),
        ("apk", "Install contoh: sudo apk add openfortivpn"),
        ("brew", "Install contoh: brew install openfortivpn"),
    ]
    .into_iter()
    .find_map(|(pkg_manager, hint)| find_in_path(pkg_manager).map(|_| hint))
}

fn sudoers_hint(binary_path: &str) -> String {
    format!(
        "Tambahkan via visudo: <username> ALL=(root) NOPASSWD: {}",
        binary_path
    )
}

fn bool_flag(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

#[derive(Debug, Clone, Copy)]
struct EffectiveNetworkOptions {
    set_routes: bool,
    set_dns: bool,
    pppd_use_peerdns: bool,
    half_internet_routes: bool,
    mode_label: &'static str,
    fallback_legacy_defaults: bool,
}

fn resolve_network_options(
    set_routes: bool,
    set_dns: bool,
    pppd_use_peerdns: bool,
    half_internet_routes: bool,
    route_targets: &[RouteTarget],
) -> EffectiveNetworkOptions {
    let explicit_defaults = set_routes && set_dns && pppd_use_peerdns && !half_internet_routes;
    let all_disabled = !set_routes && !set_dns && !pppd_use_peerdns && !half_internet_routes;

    if all_disabled && route_targets.is_empty() {
        return EffectiveNetworkOptions {
            set_routes: true,
            set_dns: true,
            pppd_use_peerdns: true,
            half_internet_routes: false,
            mode_label: "legacy-default",
            fallback_legacy_defaults: true,
        };
    }

    let mode_label = if !route_targets.is_empty() {
        "custom-routes"
    } else if explicit_defaults {
        "default"
    } else {
        "custom"
    };

    EffectiveNetworkOptions {
        set_routes,
        set_dns,
        pppd_use_peerdns,
        half_internet_routes,
        mode_label,
        fallback_legacy_defaults: false,
    }
}

// --- Build Command ------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
fn build_command(
    binary_path: &str,
    host: &str,
    port: u16,
    username: &str,
    trusted_cert: Option<&str>,
    network: EffectiveNetworkOptions,
    method: &PrivilegeMethod,
    ifname: &str,
) -> Command {
    let mut vpn_args: Vec<String> =
        vec![format!("{}:{}", host, port), "-u".into(), username.into()];

    if let Some(hash) = trusted_cert {
        vpn_args.push("--trusted-cert".into());
        vpn_args.push(hash.into());
    }
    vpn_args.push(format!(
        "--set-routes={}",
        if network.set_routes { "1" } else { "0" }
    ));
    vpn_args.push(format!(
        "--set-dns={}",
        if network.set_dns { "1" } else { "0" }
    ));
    vpn_args.push(format!(
        "--pppd-use-peerdns={}",
        if network.pppd_use_peerdns { "1" } else { "0" }
    ));
    vpn_args.push(format!(
        "--half-internet-routes={}",
        if network.half_internet_routes {
            "1"
        } else {
            "0"
        }
    ));

    // Only Linux pppd can name its interface; macOS kernel assigns the next free pppN itself.
    if cfg!(target_os = "linux") {
        vpn_args.push(format!("--pppd-ifname={}", ifname));
    }

    let mut cmd = match method {
        PrivilegeMethod::AlreadyRoot => Command::new(binary_path),
        PrivilegeMethod::SudoNoPassword => {
            let mut c = Command::new("sudo");
            c.arg("-n");
            c.arg(binary_path);
            c
        }
        PrivilegeMethod::SudoWithPassword => {
            let mut c = Command::new("sudo");
            c.arg("-S");
            c.arg(binary_path);
            c
        }
        PrivilegeMethod::Unavailable => {
            let mut c = Command::new("sudo");
            c.arg("-n");
            c.arg(binary_path);
            c
        }
    };

    cmd.args(&vpn_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(false);

    cmd
}

// --- Connect -----------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    session_id: u64,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    sudo_password: Option<String>,
    trusted_cert: Option<String>,
    set_routes: bool,
    set_dns: bool,
    pppd_use_peerdns: bool,
    half_internet_routes: bool,
    route_whitelist: String,
    ifname: String,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    pid_store: Arc<Mutex<Option<u32>>>,
    stdin_store: Arc<AsyncMutex<Option<ChildStdin>>>,
    waiting_for_input_flag: Arc<Mutex<bool>>,
) -> Result<()> {
    if host.is_empty() || username.is_empty() || password.is_empty() {
        bail!("Host, username, dan password tidak boleh kosong");
    }

    let _ = event_tx.send(AppEvent::LogLine {
        session_id,
        line: format!(
            "[VPN] Memulai koneksi{}",
            if trusted_cert.is_some() {
                " dengan trusted cert"
            } else {
                ""
            }
        ),
    });
    let _ = event_tx.send(AppEvent::DebugLog(format!(
        "[VPN] Target {}:{} sebagai {}",
        host, port, username
    )));

    if let Some(hint) = detect_install_hint() {
        let _ = event_tx.send(AppEvent::DebugLog(format!(
            "[VPN] Hint install openfortivpn: {}",
            hint
        )));
    }

    let binary_path = resolve_openfortivpn_path().ok_or_else(|| {
        let mut message = String::from(
            "Binary openfortivpn tidak ditemukan. Install openfortivpn terlebih dahulu (contoh path: /usr/bin/openfortivpn atau /usr/sbin/openfortivpn).",
        );
        if let Some(hint) = detect_install_hint() {
            message.push(' ');
            message.push_str(hint);
        }
        anyhow::anyhow!(message)
    })?;

    let binary_path_str = binary_path.to_string_lossy().into_owned();
    let _ = event_tx.send(AppEvent::DebugLog(format!(
        "[VPN] Binary openfortivpn terdeteksi di {}",
        binary_path_str
    )));

    let method = detect_privilege_for_binary(&binary_path_str, &event_tx).await;

    if method == PrivilegeMethod::Unavailable {
        bail!(
            "openfortivpn memerlukan root, tapi akses sudo tidak tersedia. {}",
            sudoers_hint(&binary_path_str)
        );
    }

    let _ = event_tx.send(AppEvent::DebugLog(format!(
        "[PRIV] Metode: {}",
        method.label()
    )));
    let route_targets = parse_route_targets(&route_whitelist)?;
    let network = resolve_network_options(
        set_routes,
        set_dns,
        pppd_use_peerdns,
        half_internet_routes,
        &route_targets,
    );
    let _ = event_tx.send(AppEvent::DebugLog(format!(
        "[VPN] Mode network: {}",
        network.mode_label
    )));
    let _ = event_tx.send(AppEvent::DebugLog(format!(
        "[VPN] Opsi route/dns efektif: set-routes={}, set-dns={}, pppd-use-peerdns={}, half-internet-routes={}",
        bool_flag(network.set_routes),
        bool_flag(network.set_dns),
        bool_flag(network.pppd_use_peerdns),
        bool_flag(network.half_internet_routes)
    )));
    if network.fallback_legacy_defaults {
        let _ = event_tx.send(AppEvent::LogLine {
            session_id,
            line: "[VPN] Opsi advanced kosong. Menggunakan route/DNS default openfortivpn agar koneksi tetap berfungsi.".into(),
        });
    }
    if !route_targets.is_empty() {
        let _ = event_tx.send(AppEvent::DebugLog(format!(
            "[VPN] Auto-route targets: {}",
            route_targets
                .iter()
                .map(RouteTarget::display)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    } else if !network.set_routes {
        let _ = event_tx.send(AppEvent::LogLine {
            session_id,
            line: "[ROUTE] Tunnel aktif tanpa route otomatis. Isi 'Auto Route Targets' agar traffic diarahkan ke VPN ini.".into(),
        });
    }

    let mut cmd = build_command(
        &binary_path_str,
        host,
        port,
        username,
        trusted_cert.as_deref(),
        network,
        &method,
        &ifname,
    );
    let _ = event_tx.send(AppEvent::LogLine {
        session_id,
        line: format!("[VPN] Interface target: {}", ifname),
    });
    let mut child: Child = cmd.spawn()?;

    if let Some(pid) = child.id() {
        *pid_store.lock().unwrap() = Some(pid);
        let _ = event_tx.send(AppEvent::DebugLog(format!("[VPN] PID: {}", pid)));
    }

    let mut stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => bail!("Tidak bisa mengambil stdin child process"),
    };

    if method == PrivilegeMethod::SudoWithPassword {
        let sp = sudo_password.as_deref().unwrap_or("");
        if sp.is_empty() {
            bail!("Sudo password diperlukan untuk metode sudo -S");
        }
        stdin.write_all(format!("{}\n", sp).as_bytes()).await?;
        stdin.flush().await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    stdin
        .write_all(format!("{}\n", password).as_bytes())
        .await?;
    stdin.flush().await?;

    *stdin_store.lock().await = Some(stdin);

    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");

    let cert_buf: Arc<Mutex<CertBuffer>> = Arc::new(Mutex::new(CertBuffer::default()));
    let token_requested_flag = Arc::new(Mutex::new(false));
    let gateway_connected = Arc::new(Mutex::new(false));
    let speed_monitor_started = Arc::new(AtomicBool::new(false));
    let stop_speed_monitor = Arc::new(AtomicBool::new(false));
    let output_tail = Arc::new(Mutex::new(VecDeque::new()));
    let initial_net_stats = read_net_stats().await.unwrap_or_default();

    let tx1 = event_tx.clone();
    let cert_buf1 = cert_buf.clone();
    let flag1 = waiting_for_input_flag.clone();
    let token_flag1 = token_requested_flag.clone();
    let gateway_flag1 = gateway_connected.clone();
    let speed_started1 = speed_monitor_started.clone();
    let stop_speed1 = stop_speed_monitor.clone();
    let output_tail1 = output_tail.clone();
    let route_targets1 = route_targets.clone();
    let method1 = method.clone();
    let sudo_password1 = sudo_password.clone();
    let initial_stats1 = initial_net_stats.clone();
    let ifname1 = ifname.clone();
    tokio::spawn(async move {
        read_stream(
            session_id,
            stdout,
            tx1,
            false,
            cert_buf1,
            flag1,
            token_flag1,
            gateway_flag1,
            speed_started1,
            stop_speed1,
            output_tail1,
            route_targets1,
            method1,
            sudo_password1,
            initial_stats1,
            ifname1,
        )
        .await;
    });

    let tx2 = event_tx.clone();
    let cert_buf2 = cert_buf.clone();
    let flag2 = waiting_for_input_flag.clone();
    let token_flag2 = token_requested_flag.clone();
    let gateway_flag2 = gateway_connected.clone();
    let speed_started2 = speed_monitor_started.clone();
    let stop_speed2 = stop_speed_monitor.clone();
    let output_tail2 = output_tail.clone();
    let route_targets2 = route_targets.clone();
    let method2 = method.clone();
    let sudo_password2 = sudo_password.clone();
    let initial_stats2 = initial_net_stats;
    tokio::spawn(async move {
        read_stream(
            session_id,
            stderr,
            tx2,
            true,
            cert_buf2,
            flag2,
            token_flag2,
            gateway_flag2,
            speed_started2,
            stop_speed2,
            output_tail2,
            route_targets2,
            method2,
            sudo_password2,
            initial_stats2,
            ifname,
        )
        .await;
    });

    let tx_waiter = event_tx.clone();
    let pid_store_waiter = pid_store.clone();
    let cert_buf_waiter = cert_buf.clone();
    let flag_waiter = waiting_for_input_flag.clone();
    let stop_speed_waiter = stop_speed_monitor.clone();
    let stdin_store_waiter = stdin_store.clone();
    let output_tail_waiter = output_tail.clone();

    tokio::spawn(async move {
        wait_for_process(
            session_id,
            child,
            tx_waiter,
            pid_store_waiter,
            cert_buf_waiter,
            flag_waiter,
            stop_speed_waiter,
            stdin_store_waiter,
            output_tail_waiter,
        )
        .await;
    });

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn read_stream(
    session_id: u64,
    stream: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    tx: mpsc::UnboundedSender<AppEvent>,
    _is_stderr: bool,
    cert_buf: Arc<Mutex<CertBuffer>>,
    waiting_flag: Arc<Mutex<bool>>,
    token_requested: Arc<Mutex<bool>>,
    gateway_connected: Arc<Mutex<bool>>,
    speed_monitor_started: Arc<AtomicBool>,
    stop_speed_monitor: Arc<AtomicBool>,
    output_tail: Arc<Mutex<VecDeque<String>>>,
    route_targets: Vec<RouteTarget>,
    privilege_method: PrivilegeMethod,
    sudo_password: Option<String>,
    initial_net_stats: HashMap<String, NetStats>,
    ifname: String,
) {
    let ctx = StreamContext {
        session_id,
        tx,
        cert_buf,
        waiting_flag,
        token_requested,
        gateway_connected,
        speed_monitor_started,
        stop_speed_monitor,
        output_tail,
        route_targets,
        privilege_method,
        sudo_password,
        initial_net_stats,
        ifname,
    };

    let mut stream = stream;
    let mut read_buf = [0_u8; 1024];
    let mut pending = String::new();

    loop {
        let bytes_read = match stream.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = ctx.tx.send(AppEvent::DebugLog(format!(
                    "[VPN] Gagal baca output: {}",
                    e
                )));
                break;
            }
        };

        let chunk = String::from_utf8_lossy(&read_buf[..bytes_read]);
        pending.push_str(&chunk);
        ctx.maybe_request_token(&pending.to_lowercase(), pending.trim());

        while let Some(newline_idx) = pending.find('\n') {
            let line: String = pending.drain(..=newline_idx).collect();
            ctx.process_line(line.trim_end_matches(['\r', '\n']));
        }

        if pending.len() > 8192 {
            ctx.process_line(pending.trim_end_matches(['\r', '\n']));
            pending.clear();
        }
    }

    if !pending.trim().is_empty() {
        ctx.process_line(pending.trim_end_matches(['\r', '\n']));
    }
}

struct StreamContext {
    session_id: u64,
    tx: mpsc::UnboundedSender<AppEvent>,
    cert_buf: Arc<Mutex<CertBuffer>>,
    waiting_flag: Arc<Mutex<bool>>,
    token_requested: Arc<Mutex<bool>>,
    gateway_connected: Arc<Mutex<bool>>,
    speed_monitor_started: Arc<AtomicBool>,
    stop_speed_monitor: Arc<AtomicBool>,
    output_tail: Arc<Mutex<VecDeque<String>>>,
    route_targets: Vec<RouteTarget>,
    privilege_method: PrivilegeMethod,
    sudo_password: Option<String>,
    initial_net_stats: HashMap<String, NetStats>,
    ifname: String,
}

impl StreamContext {
    fn maybe_request_token(&self, text_lower: &str, display_text: &str) -> bool {
        if !is_token_prompt(text_lower) || *self.token_requested.lock().unwrap() {
            return false;
        }

        *self.token_requested.lock().unwrap() = true;
        let _ = self.tx.send(AppEvent::DebugLog(format!(
            "[VPN] Prompt token terdeteksi: {}",
            display_text
        )));
        let _ = self.tx.send(AppEvent::LogLine {
            session_id: self.session_id,
            line: "[VPN] Menunggu token OTP...".into(),
        });
        let _ = self.tx.send(AppEvent::NeedToken(self.session_id));
        let _ = self.tx.send(AppEvent::StateChanged {
            session_id: self.session_id,
            state: VpnState::WaitingToken,
        });
        *self.waiting_flag.lock().unwrap() = true;
        true
    }

    fn process_line(&self, line: &str) {
        self.record_output_tail(line);
        let line_lower = line.to_lowercase();

        {
            let mut buf = self.cert_buf.lock().unwrap();
            buf.feed(&line);
        }

        if line_lower.contains("connected to gateway") && !*self.gateway_connected.lock().unwrap() {
            *self.gateway_connected.lock().unwrap() = true;
            let _ = self
                .tx
                .send(AppEvent::DebugLog(format!("[VPN] {}", line.trim())));
            return;
        }

        if self.maybe_request_token(&line_lower, line.trim()) {
            return;
        }

        if line_lower.contains("tunnel is up") {
            let _ = self
                .tx
                .send(AppEvent::DebugLog(format!("[VPN] {}", line.trim())));
            let _ = self.tx.send(AppEvent::StateChanged {
                session_id: self.session_id,
                state: VpnState::Connected,
            });
            *self.waiting_flag.lock().unwrap() = false;

            if !self.speed_monitor_started.swap(true, Ordering::SeqCst) {
                let tx_speed = self.tx.clone();
                let stop_speed = self.stop_speed_monitor.clone();
                let initial_stats = self.initial_net_stats.clone();
                let session_id = self.session_id;
                let ifname = self.ifname.clone();
                tokio::spawn(async move {
                    monitor_connection_speed(session_id, tx_speed, initial_stats, stop_speed, ifname)
                        .await;
                });
            }

            let tx_diag = self.tx.clone();
            let session_id = self.session_id;
            let initial_stats = self.initial_net_stats.clone();
            let route_targets = self.route_targets.clone();
            let privilege_method = self.privilege_method.clone();
            let sudo_password = self.sudo_password.clone();
            let ifname = self.ifname.clone();
            tokio::spawn(async move {
                run_post_connect_diagnostics(
                    session_id,
                    tx_diag,
                    initial_stats,
                    route_targets,
                    privilege_method,
                    sudo_password,
                    ifname,
                )
                .await;
            });

            return;
        }

        if line_lower.contains("password:") && line_lower.contains("vpn account") {
            return;
        }

        if !line.trim().is_empty() {
            let prefix = if line_lower.contains("error") {
                "[ERR] "
            } else if line_lower.contains("warn") {
                "[Peringatan] "
            } else {
                "[VPN] "
            };
            let _ = self
                .tx
                .send(AppEvent::DebugLog(format!("{}{}", prefix, line.trim())));
        }
    }

    fn record_output_tail(&self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        let mut tail = self.output_tail.lock().unwrap();
        if tail.len() >= 6 {
            tail.pop_front();
        }
        tail.push_back(line.to_string());
    }
}

fn is_token_prompt(line_lower: &str) -> bool {
    let has_token_term = line_lower.contains("two-factor")
        || line_lower.contains("2fa")
        || line_lower.contains("otp")
        || line_lower.contains("one-time")
        || line_lower.contains("verification code")
        || line_lower.contains("authenticator")
        || line_lower.contains("token:");

    if has_token_term {
        return true;
    }

    line_lower.contains("token")
        && (line_lower.contains(':')
            || line_lower.contains("enter")
            || line_lower.contains("input")
            || line_lower.contains("please"))
        && !line_lower.contains("trusted-cert")
        && !line_lower.contains("session token")
}

async fn wait_for_process(
    session_id: u64,
    mut child: Child,
    tx: mpsc::UnboundedSender<AppEvent>,
    pid_store: Arc<Mutex<Option<u32>>>,
    cert_buf: Arc<Mutex<CertBuffer>>,
    waiting_flag: Arc<Mutex<bool>>,
    stop_speed_monitor: Arc<AtomicBool>,
    stdin_store: Arc<AsyncMutex<Option<ChildStdin>>>,
    output_tail: Arc<Mutex<VecDeque<String>>>,
) {
    let status = child.wait().await;
    stop_speed_monitor.store(true, Ordering::SeqCst);
    *pid_store.lock().unwrap() = None;
    *stdin_store.lock().await = None;

    let cert_info = cert_buf.lock().unwrap().try_emit();
    if let Some(info) = cert_info {
        let _ = tx.send(AppEvent::DebugLog(format!(
            "[CERT] Untrusted: CN={}",
            info.subject_cn
        )));
        let _ = tx.send(AppEvent::CertError {
            session_id,
            cert: info,
        });
        return;
    }

    let was_waiting = *waiting_flag.lock().unwrap();

    match status {
        Ok(exit) => {
            if was_waiting {
                let _ = tx.send(AppEvent::DebugLog(
                    "[VPN] Peringatan: Koneksi terputus saat menunggu token".into(),
                ));
                *waiting_flag.lock().unwrap() = false;
                let _ = tx.send(AppEvent::StateChanged {
                    session_id,
                    state: VpnState::Error("Koneksi terputus saat menunggu token OTP".into()),
                });
            } else if exit.success() {
                let _ = tx.send(AppEvent::DebugLog("[VPN] Koneksi ditutup".into()));
                let _ = tx.send(AppEvent::StateChanged {
                    session_id,
                    state: VpnState::Disconnected,
                });
            } else {
                let code = exit.code().unwrap_or(-1);
                let _ = tx.send(AppEvent::DebugLog(format!("[VPN] Exit code: {}", code)));
                let tail = output_tail
                    .lock()
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                let details = if tail.is_empty() {
                    format!("openfortivpn keluar dengan kode {}", code)
                } else {
                    format!(
                        "openfortivpn keluar dengan kode {}: {}",
                        code,
                        tail.join(" | ")
                    )
                };
                let _ = tx.send(AppEvent::StateChanged {
                    session_id,
                    state: VpnState::Error(details),
                });
            }
        }
        Err(e) => {
            let _ = tx.send(AppEvent::DebugLog(format!("[VPN] Error: {}", e)));
            let _ = tx.send(AppEvent::StateChanged {
                session_id,
                state: VpnState::Disconnected,
            });
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct NetStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

async fn monitor_connection_speed(
    session_id: u64,
    tx: mpsc::UnboundedSender<AppEvent>,
    initial_stats: HashMap<String, NetStats>,
    stop: Arc<AtomicBool>,
    ifname: String,
) {
    const SAMPLE_SECS: u64 = 5;

    let mut selected_iface: Option<String> = None;
    let mut previous_stats = read_net_stats().await.unwrap_or_default();

    loop {
        tokio::time::sleep(Duration::from_secs(SAMPLE_SECS)).await;

        if stop.load(Ordering::SeqCst) {
            break;
        }

        let current_stats = match read_net_stats().await {
            Ok(stats) => stats,
            Err(e) => {
                let _ = tx.send(AppEvent::DebugLog(format!(
                    "[SPEED] Gagal membaca statistik interface: {}",
                    e
                )));
                break;
            }
        };

        let iface = match selected_iface.as_deref() {
            Some(iface) if current_stats.contains_key(iface) => iface.to_string(),
            _ => match detect_openfortivpn_interface(&ifname, &initial_stats, &current_stats) {
                Some(iface) => {
                    let _ = tx.send(AppEvent::LogLine {
                        session_id,
                        line: format!("[SPEED] Monitor aktif di interface {}", iface),
                    });
                    selected_iface = Some(iface.clone());
                    iface
                }
                None => {
                    previous_stats = current_stats;
                    continue;
                }
            },
        };

        if let (Some(previous), Some(current)) =
            (previous_stats.get(&iface), current_stats.get(&iface))
        {
            let rx_per_sec = current.rx_bytes.saturating_sub(previous.rx_bytes) / SAMPLE_SECS;
            let tx_per_sec = current.tx_bytes.saturating_sub(previous.tx_bytes) / SAMPLE_SECS;

            let _ = tx.send(AppEvent::LogLine {
                session_id,
                line: format!(
                    "[SPEED] down {}/s up {}/s ({})",
                    format_speed(rx_per_sec),
                    format_speed(tx_per_sec),
                    iface
                ),
            });

            let initial = initial_stats.get(&iface).copied().unwrap_or_default();
            let rx_total = current.rx_bytes.saturating_sub(initial.rx_bytes);
            let tx_total = current.tx_bytes.saturating_sub(initial.tx_bytes);

            let _ = tx.send(AppEvent::SpeedUpdate {
                session_id,
                interface: iface.clone(),
                rx_bps: rx_per_sec,
                tx_bps: tx_per_sec,
                rx_total,
                tx_total,
            });
        }

        previous_stats = current_stats;
    }
}

async fn read_net_stats() -> Result<HashMap<String, NetStats>> {
    read_platform_net_stats().await
}

async fn run_post_connect_diagnostics(
    session_id: u64,
    tx: mpsc::UnboundedSender<AppEvent>,
    initial_stats: HashMap<String, NetStats>,
    route_targets: Vec<RouteTarget>,
    privilege_method: PrivilegeMethod,
    sudo_password: Option<String>,
    ifname: String,
) {
    match collect_post_connect_diagnostics(
        session_id,
        &tx,
        &initial_stats,
        &route_targets,
        &privilege_method,
        sudo_password.as_deref(),
        &ifname,
    )
    .await
    {
        Ok((detected_interface, lines)) => {
            if let Some(interface) = detected_interface {
                let _ = tx.send(AppEvent::InterfaceDetected {
                    session_id,
                    interface,
                });
            }
            for line in lines {
                let _ = tx.send(AppEvent::LogLine { session_id, line });
            }
        }
        Err(e) => {
            let _ = tx.send(AppEvent::DebugLog(format!(
                "[DIAG] Gagal menjalankan diagnostic VPN: {}",
                e
            )));
        }
    }
}

async fn collect_post_connect_diagnostics(
    session_id: u64,
    tx: &mpsc::UnboundedSender<AppEvent>,
    initial_stats: &HashMap<String, NetStats>,
    route_targets: &[RouteTarget],
    privilege_method: &PrivilegeMethod,
    sudo_password: Option<&str>,
    ifname: &str,
) -> Result<(Option<String>, Vec<String>)> {
    let mut lines = vec!["[DIAG] Memeriksa route/DNS setelah tunnel up...".to_string()];

    let stats = read_net_stats().await.unwrap_or_default();
    let detected_interface = detect_openfortivpn_interface(ifname, initial_stats, &stats);
    let vpn_ifaces: Vec<String> = stats
        .keys()
        .filter(|iface| is_likely_vpn_interface(iface))
        .cloned()
        .collect();
    if vpn_ifaces.is_empty() {
        lines.push("[DIAG] Peringatan: tidak menemukan interface VPN dari statistik OS".into());
    } else {
        lines.push(format!(
            "[DIAG] Interface VPN terdeteksi: {}",
            vpn_ifaces.join(", ")
        ));
    }

    if let Some(interface) = detected_interface.as_deref() {
        lines.push(format!("[DIAG] Interface openfortivpn: {}", interface));
        append_dual_vpn_guidance(&mut lines, interface, &vpn_ifaces, route_targets);
        if !route_targets.is_empty() {
            apply_route_targets(
                session_id,
                tx,
                interface,
                route_targets,
                privilege_method,
                sudo_password,
                &mut lines,
            )
            .await;
        }
    } else if !route_targets.is_empty() {
        lines.push(
            "[DIAG] Auto-route dilewati: interface openfortivpn tidak terdeteksi dengan pasti"
                .into(),
        );
    }

    append_platform_diagnostics(&mut lines).await;
    Ok((detected_interface, lines))
}

fn append_dual_vpn_guidance(
    lines: &mut Vec<String>,
    openfortivpn_interface: &str,
    vpn_ifaces: &[String],
    route_targets: &[RouteTarget],
) {
    #[cfg(target_os = "macos")]
    {
        let other_ifaces: Vec<&str> = vpn_ifaces
            .iter()
            .map(String::as_str)
            .filter(|iface| *iface != openfortivpn_interface)
            .collect();

        if other_ifaces.is_empty() {
            return;
        }

        lines.push(format!(
            "[DIAG] VPN lain juga aktif: {}",
            other_ifaces.join(", ")
        ));

        if openfortivpn_interface.starts_with("ppp") && route_targets.is_empty() {
            lines.push(
                "[DIAG] macOS dual-VPN terdeteksi. Route atau DNS jaringan privat masih bisa dimenangkan interface VPN lain."
                    .into(),
            );
            lines.push(
                "[DIAG] Jika resource dari VPN openfortivpn belum bisa diakses, isi 'Auto Route Targets' dengan subnet/IP tujuan agar diarahkan paksa ke interface ini."
                    .into(),
            );
        }
    }
}

/// Prefer the pppN reserved for this session; otherwise (macOS picks the unit itself)
/// the lowest ppp interface that appeared after this connection started.
fn detect_openfortivpn_interface(
    expected: &str,
    initial: &HashMap<String, NetStats>,
    current: &HashMap<String, NetStats>,
) -> Option<String> {
    let is_new = |iface: &str| current.contains_key(iface) && !initial.contains_key(iface);
    if is_new(expected) {
        return Some(expected.to_string());
    }
    current
        .keys()
        .filter(|iface| iface.starts_with("ppp") && is_new(iface))
        .min_by_key(|iface| ppp_unit(iface))
        .cloned()
        .or_else(|| current.contains_key(expected).then(|| expected.to_string()))
}

fn ppp_unit(iface: &str) -> u32 {
    iface
        .strip_prefix("ppp")
        .and_then(|n| n.parse().ok())
        .unwrap_or(u32::MAX)
}

/// Lowest pppN that is neither present on the system nor reserved by another session.
pub async fn pick_ppp_ifname(reserved: &[String]) -> String {
    let existing = read_net_stats().await.unwrap_or_default();
    (0..)
        .map(|n| format!("ppp{}", n))
        .find(|name| !existing.contains_key(name) && !reserved.contains(name))
        .expect("infinite range")
}

/// True when some physical interface (WiFi/Ethernet) is up with a usable IPv4 address.
// ponytail: name-based filter for virtual interfaces; extend the prefix list if a VM/bridge
// keeps reporting "online" while WiFi is off.
pub fn has_physical_network() -> bool {
    const VIRTUAL: [&str; 10] = [
        "lo", "docker", "br-", "veth", "virbr", "bridge", "awdl", "llw", "anpi", "vmnet",
    ];
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return true; // unknown -> don't claim offline
    }
    let mut online = false;
    let mut cur = addrs;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null()
            || i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET
        {
            continue;
        }
        let flags = ifa.ifa_flags as c_int;
        if flags & libc::IFF_UP == 0
            || flags & libc::IFF_RUNNING == 0
            || flags & libc::IFF_LOOPBACK != 0
        {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if is_likely_vpn_interface(&name) || VIRTUAL.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let ip = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) }.sin_addr.s_addr;
        if !Ipv4Addr::from(u32::from_be(ip)).is_link_local() {
            online = true;
            break;
        }
    }
    unsafe { libc::freeifaddrs(addrs) };
    online
}

async fn apply_route_targets(
    session_id: u64,
    tx: &mpsc::UnboundedSender<AppEvent>,
    interface: &str,
    route_targets: &[RouteTarget],
    privilege_method: &PrivilegeMethod,
    sudo_password: Option<&str>,
    lines: &mut Vec<String>,
) {
    lines.push(format!(
        "[DIAG] Menyiapkan {} auto-route ke {}",
        route_targets.len(),
        interface
    ));

    for target in route_targets {
        match ensure_route_target(interface, target, privilege_method, sudo_password).await {
            Ok(RouteApplyResult::Added) => lines.push(format!(
                "[ROUTE] {} diarahkan ke {}",
                target.display(),
                interface
            )),
            Ok(RouteApplyResult::AlreadyPresent) => lines.push(format!(
                "[ROUTE] {} sudah memakai {}",
                target.display(),
                interface
            )),
            Err(err) => {
                let message = format!(
                    "[ROUTE] Gagal arahkan {} ke {}: {}",
                    target.display(),
                    interface,
                    err
                );
                lines.push(message.clone());
                let _ = tx.send(AppEvent::DebugLog(format!(
                    "[ROUTE][session={}] {}",
                    session_id, message
                )));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteApplyResult {
    Added,
    AlreadyPresent,
}

async fn ensure_route_target(
    interface: &str,
    target: &RouteTarget,
    privilege_method: &PrivilegeMethod,
    sudo_password: Option<&str>,
) -> Result<RouteApplyResult> {
    if route_points_to_interface(target, interface)
        .await
        .unwrap_or(false)
    {
        return Ok(RouteApplyResult::AlreadyPresent);
    }

    let (kind, destination) = route_kind_and_destination(target);

    let _ = privileged_command(
        "route",
        &["-n", "delete", kind, &destination],
        privilege_method,
        sudo_password,
    )
    .await;

    privileged_command(
        "route",
        &["-n", "add", kind, &destination, "-interface", interface],
        privilege_method,
        sudo_password,
    )
    .await?;

    Ok(RouteApplyResult::Added)
}

async fn route_points_to_interface(target: &RouteTarget, interface: &str) -> Result<bool> {
    let destination = target.route_get_target();
    let output = command_stdout("route", &["-n", "get", &destination]).await?;
    Ok(output.lines().any(|line| {
        line.trim()
            .strip_prefix("interface:")
            .is_some_and(|value| value.trim() == interface)
    }))
}

fn route_kind_and_destination(target: &RouteTarget) -> (&'static str, String) {
    match target {
        RouteTarget::Host(addr) => ("-host", addr.to_string()),
        RouteTarget::Network { addr, prefix } => ("-net", format!("{addr}/{prefix}")),
    }
}

async fn privileged_command(
    program: &str,
    args: &[&str],
    privilege_method: &PrivilegeMethod,
    sudo_password: Option<&str>,
) -> Result<()> {
    let mut cmd = match privilege_method {
        PrivilegeMethod::AlreadyRoot => Command::new(program),
        PrivilegeMethod::SudoNoPassword | PrivilegeMethod::SudoWithPassword => {
            let mut command = Command::new("sudo");
            command.arg("-n");
            command.arg(program);
            command
        }
        PrivilegeMethod::Unavailable => bail!("Akses root tidak tersedia untuk update route"),
    };

    cmd.args(args);
    let output = cmd.output().await?;
    if output.status.success() {
        return Ok(());
    }

    if *privilege_method != PrivilegeMethod::SudoWithPassword {
        bail!(
            "{} gagal: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let Some(password) = sudo_password else {
        bail!("Password sudo diperlukan untuk update route otomatis");
    };

    let mut fallback = Command::new("sudo");
    fallback.arg("-S");
    fallback.arg(program);
    fallback.args(args);
    fallback.stdin(std::process::Stdio::piped());
    fallback.stdout(std::process::Stdio::null());
    fallback.stderr(std::process::Stdio::piped());

    let mut child = fallback.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Gagal membuka stdin sudo"))?;
    stdin
        .write_all(format!("{}\n", password).as_bytes())
        .await?;
    stdin.flush().await?;
    drop(stdin);

    let output = child.wait_with_output().await?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} gagal: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}

#[cfg(target_os = "macos")]
async fn append_platform_diagnostics(lines: &mut Vec<String>) {
    match command_stdout("netstat", &["-rn", "-f", "inet"]).await {
        Ok(route_table) => {
            let route_lines: Vec<&str> = route_table
                .lines()
                .filter(|line| {
                    line.starts_with("default")
                        || line.contains(" ppp")
                        || line.contains(" utun")
                        || line.contains(" 10.")
                        || line.contains(" 172.")
                        || line.contains(" 192.168.")
                })
                .take(10)
                .collect();

            if route_lines.is_empty() {
                lines.push("[DIAG] Route IPv4: tidak ada ringkasan route VPN".into());
            } else {
                lines.push(format!("[DIAG] Route IPv4: {}", route_lines.join(" | ")));
            }
        }
        Err(e) => lines.push(format!("[DIAG] Gagal baca route IPv4: {}", e)),
    }

    match command_stdout("scutil", &["--dns"]).await {
        Ok(dns) => {
            let dns_summary: Vec<&str> = dns
                .lines()
                .filter(|line| line.contains("nameserver") || line.contains("if_index"))
                .take(8)
                .collect();
            if dns_summary.is_empty() {
                lines.push("[DIAG] DNS: tidak ada resolver aktif".into());
            } else {
                lines.push(format!("[DIAG] DNS: {}", dns_summary.join(" | ")));
            }
        }
        Err(e) => lines.push(format!("[DIAG] Gagal baca DNS: {}", e)),
    }
}

#[cfg(target_os = "linux")]
async fn append_platform_diagnostics(lines: &mut Vec<String>) {
    match command_stdout("ip", &["route"]).await {
        Ok(route_table) => {
            let route_lines: Vec<&str> = route_table
                .lines()
                .filter(|line| {
                    line.starts_with("default")
                        || line.contains(" ppp")
                        || line.contains(" tun")
                        || line.contains(" tap")
                        || line.starts_with("10.")
                        || line.starts_with("172.")
                        || line.starts_with("192.168.")
                })
                .take(10)
                .collect();
            if route_lines.is_empty() {
                lines.push("[DIAG] Route IPv4: tidak ada ringkasan route VPN".into());
            } else {
                lines.push(format!("[DIAG] Route IPv4: {}", route_lines.join(" | ")));
            }
        }
        Err(e) => lines.push(format!("[DIAG] Gagal baca route IPv4: {}", e)),
    }

    match tokio::fs::read_to_string("/etc/resolv.conf").await {
        Ok(resolv) => {
            let dns_summary: Vec<&str> = resolv
                .lines()
                .filter(|line| line.starts_with("nameserver") || line.starts_with("search"))
                .take(8)
                .collect();
            if dns_summary.is_empty() {
                lines.push("[DIAG] DNS: /etc/resolv.conf tidak berisi resolver".into());
            } else {
                lines.push(format!("[DIAG] DNS: {}", dns_summary.join(" | ")));
            }
        }
        Err(e) => lines.push(format!("[DIAG] Gagal baca DNS: {}", e)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn append_platform_diagnostics(lines: &mut Vec<String>) {
    lines.push("[DIAG] Diagnostic route/DNS belum tersedia untuk OS ini".into());
}

async fn command_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output().await?;
    if !output.status.success() {
        bail!("{} gagal dengan status {}", program, output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "linux")]
async fn read_platform_net_stats() -> Result<HashMap<String, NetStats>> {
    let content = tokio::fs::read_to_string("/proc/net/dev").await?;
    let mut stats = HashMap::new();

    for line in content.lines().skip(2) {
        let Some((iface, values)) = line.split_once(':') else {
            continue;
        };

        let fields: Vec<&str> = values.split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }

        let rx_bytes = fields[0].parse::<u64>().unwrap_or(0);
        let tx_bytes = fields[8].parse::<u64>().unwrap_or(0);

        stats.insert(iface.trim().to_string(), NetStats { rx_bytes, tx_bytes });
    }

    Ok(stats)
}

#[cfg(target_os = "macos")]
async fn read_platform_net_stats() -> Result<HashMap<String, NetStats>> {
    let output = Command::new("netstat").args(["-ibn"]).output().await?;
    if !output.status.success() {
        bail!("netstat -ibn gagal dengan status {}", output.status);
    }

    let content = String::from_utf8_lossy(&output.stdout);
    let mut stats = HashMap::new();
    let mut indexes: Option<(usize, usize, usize)> = None;

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }

        if fields[0] == "Name" {
            let name_idx = fields
                .iter()
                .position(|field| *field == "Name")
                .unwrap_or(0);
            let ibytes_idx = fields.iter().position(|field| *field == "Ibytes");
            let obytes_idx = fields.iter().position(|field| *field == "Obytes");

            if let (Some(ibytes_idx), Some(obytes_idx)) = (ibytes_idx, obytes_idx) {
                indexes = Some((name_idx, ibytes_idx, obytes_idx));
            }
            continue;
        }

        let Some((name_idx, ibytes_idx, obytes_idx)) = indexes else {
            continue;
        };
        if fields.len() <= name_idx || fields.len() <= ibytes_idx || fields.len() <= obytes_idx {
            continue;
        }

        let iface = fields[name_idx].trim_end_matches('*').to_string();
        let rx_bytes = fields[ibytes_idx].parse::<u64>().unwrap_or(0);
        let tx_bytes = fields[obytes_idx].parse::<u64>().unwrap_or(0);

        stats
            .entry(iface)
            .and_modify(|entry: &mut NetStats| {
                entry.rx_bytes = entry.rx_bytes.max(rx_bytes);
                entry.tx_bytes = entry.tx_bytes.max(tx_bytes);
            })
            .or_insert(NetStats { rx_bytes, tx_bytes });
    }

    Ok(stats)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn read_platform_net_stats() -> Result<HashMap<String, NetStats>> {
    Ok(HashMap::new())
}

fn is_likely_vpn_interface(iface: &str) -> bool {
    ["ppp", "tun", "tap", "utun", "vpn"]
        .iter()
        .any(|prefix| iface.starts_with(prefix))
}

fn format_speed(bytes_per_sec: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut value = bytes_per_sec as f64;
    let mut unit = UNITS[0];

    for next_unit in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next_unit;
    }

    if unit == "B" {
        format!("{} {}", bytes_per_sec, unit)
    } else {
        format!("{:.1} {}", value, unit)
    }
}

// --- Send OTP Token ----------------------------------------------------------
pub async fn send_token(
    session_id: u64,
    token: &str,
    pid_store: Arc<Mutex<Option<u32>>>,
    stdin_store: Arc<AsyncMutex<Option<ChildStdin>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<()> {
    let pid = *pid_store.lock().unwrap();
    if let Some(pid) = pid {
        let _ = event_tx.send(AppEvent::LogLine {
            session_id,
            line: format!("[TOKEN] Mengirim token ke PID {}...", pid),
        });

        let token_line = format!("{}\n", token);
        let mut stdin_guard = stdin_store.lock().await;
        let stdin = stdin_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Stdin proses VPN tidak tersedia"))?;
        stdin.write_all(token_line.as_bytes()).await?;
        stdin.flush().await?;

        let _ = event_tx.send(AppEvent::LogLine {
            session_id,
            line: "[TOKEN] Token berhasil dikirim".into(),
        });
        Ok(())
    } else {
        Err(anyhow::anyhow!("Tidak ada proses VPN aktif"))
    }
}

// --- Cert Error Parser --------------------------------------------------------
#[derive(Debug, Default)]
struct CertBuffer {
    collecting: bool,
    hash: String,
    subject_cn: String,
    subject_org: String,
    issuer_cn: String,
    raw_lines: Vec<String>,
    emitted: bool,
    in_subject: bool,
    in_issuer: bool,
}

impl CertBuffer {
    fn try_emit(&mut self) -> Option<CertInfo> {
        if self.emitted || self.hash.is_empty() {
            return None;
        }
        self.emitted = true;
        Some(CertInfo {
            hash: self.hash.clone(),
            subject_cn: self.subject_cn.clone(),
            subject_org: self.subject_org.clone(),
            issuer_cn: self.issuer_cn.clone(),
        })
    }

    fn feed(&mut self, line: &str) {
        let lower = line.to_lowercase();
        let trimmed = line.trim();

        if lower.contains("gateway certificate validation failed") {
            self.collecting = true;
            self.raw_lines.push(trimmed.to_string());
            return;
        }

        if !self.collecting {
            return;
        }

        self.raw_lines.push(trimmed.to_string());

        if lower.contains("--trusted-cert") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(hash) = parts.last()
                && hash.len() >= 32
            {
                self.hash = hash.to_string();
            }
            return;
        }

        if lower.contains("subject:") {
            self.in_subject = true;
            self.in_issuer = false;
            return;
        }
        if lower.contains("issuer:") {
            self.in_issuer = true;
            self.in_subject = false;
            return;
        }

        if trimmed.contains('=') {
            let kv: Vec<&str> = trimmed.splitn(2, '=').collect();
            if kv.len() == 2 {
                let key = kv[0].trim().to_uppercase();
                let val = kv[1].trim();
                if self.in_subject {
                    match key.as_str() {
                        "CN" => self.subject_cn = val.to_string(),
                        "O" => self.subject_org = val.to_string(),
                        _ => {}
                    }
                } else if self.in_issuer && key == "CN" {
                    self.issuer_cn = val.to_string();
                }
            }
        }

        if lower.contains("closed connection") || lower.contains("could not log out") {
            self.in_subject = false;
            self.in_issuer = false;
        }
    }
}

// --- Disconnect --------------------------------------------------------------
pub async fn disconnect(
    session_id: u64,
    pid_store: Arc<Mutex<Option<u32>>>,
    stdin_store: Arc<AsyncMutex<Option<ChildStdin>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
) -> Result<()> {
    let pid = *pid_store.lock().unwrap();
    if let Some(pid) = pid {
        let _ = event_tx.send(AppEvent::LogLine {
            session_id,
            line: format!("[VPN] Menghentikan PID {}...", pid),
        });
        let _ = send_signal(pid, SIGTERM);
        // openfortivpn logs out of the gateway before exiting; killing sudo too early
        // orphans the root openfortivpn process and leaves the tunnel up.
        for _ in 0..50 {
            if !process_exists(pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if process_exists(pid) {
            let _ = send_signal(pid, SIGKILL);
            let _ = event_tx.send(AppEvent::LogLine {
                session_id,
                line: "[VPN] Force kill dengan SIGKILL".into(),
            });
        } else {
            let _ = event_tx.send(AppEvent::LogLine {
                session_id,
                line: "[VPN] Proses berhenti".into(),
            });
        }
        *pid_store.lock().unwrap() = None;
    } else {
        // No process (already exited / never started): nothing will report the exit.
        let _ = event_tx.send(AppEvent::StateChanged {
            session_id,
            state: VpnState::Disconnected,
        });
    }
    *stdin_store.lock().await = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ifaces(names: &[&str]) -> HashMap<String, NetStats> {
        names
            .iter()
            .map(|n| (n.to_string(), NetStats::default()))
            .collect()
    }

    #[test]
    fn detects_reserved_or_newest_ppp() {
        // Linux: reserved name came up.
        let initial = ifaces(&["en0", "ppp0"]);
        assert_eq!(
            detect_openfortivpn_interface("ppp1", &initial, &ifaces(&["en0", "ppp0", "ppp1"])),
            Some("ppp1".into())
        );
        // macOS: kernel picked another unit; never claim the pre-existing ppp0.
        assert_eq!(
            detect_openfortivpn_interface("ppp1", &initial, &ifaces(&["en0", "ppp0", "ppp2"])),
            Some("ppp2".into())
        );
        // Not up yet.
        assert_eq!(
            detect_openfortivpn_interface("ppp1", &initial, &initial),
            None
        );
    }
}
