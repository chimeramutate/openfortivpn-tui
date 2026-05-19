# openfortivpn-tui

Simple terminal UI for `openfortivpn` with profile management, OTP support, multi-session support, and debug logging.

Repository: [openfortivpn-tui GitHub Repository](https://github.com/Asepimam/openfortivpn-tui?utm_source=chatgpt.com)

---

## Features

* Simple terminal-based interface
* Multiple concurrent VPN sessions
* Isolated session state management
* OTP / 2FA support
* Debug logging support
* Profile management
* Automatic process cleanup
* Lightweight and fast Rust application

---

# Requirements

Make sure `openfortivpn` is installed on your system.

## Ubuntu / Debian

```bash
sudo apt update
sudo apt install openfortivpn
```

Typical binary locations:

```text
/usr/bin/openfortivpn
/usr/sbin/openfortivpn
```

---

# Installation

## macOS via Homebrew

Install directly from Homebrew tap:

```bash
brew tap asepimam/tap
brew install openfortivpn-tui
```

Or install directly:

```bash
brew install asepimam/tap/openfortivpn-tui
```

---

## Linux via GitHub Release

Download the latest release from:

[GitHub Releases](https://github.com/Asepimam/openfortivpn-tui/releases?utm_source=chatgpt.com)

Example:

```bash
wget https://github.com/Asepimam/openfortivpn-tui/releases/latest/download/openfortivpn-tui-linux.zip
unzip openfortivpn-tui-linux.zip
chmod +x openfortivpn-tui
./openfortivpn-tui
```

---

# Running the Application

## Normal Mode

Using Cargo:

```bash
cargo run
```

Using compiled binary:

```bash
./target/debug/openfortivpn-tui
```

---

# Debug Logging

By default, raw `openfortivpn` process output is not shown in the UI. The application dashboard only displays connection status and important events.

To enable debug logging:

```bash
cargo run -- -d
```

Or:

```bash
./target/debug/openfortivpn-tui -d
```

Debug logs are written to:

```text
/tmp/openfortivpn-tui.log
```

Debug mode is useful for:

* VPN connection troubleshooting
* OTP / authentication debugging
* Inspecting raw `openfortivpn` output

Sensitive OTP tokens are never written to the UI or debug log.

---

# Sudoers Configuration

`openfortivpn` requires root privileges.

The recommended and safest approach is to allow passwordless execution only for the `openfortivpn` binary instead of granting unrestricted sudo access.

Edit sudoers safely:

```bash
sudo visudo
```

Add one of the following rules depending on your binary location.

If installed at `/usr/bin/openfortivpn`:

```sudoers
<username> ALL=(root) NOPASSWD: /usr/bin/openfortivpn
```

If installed at `/usr/sbin/openfortivpn`:

```sudoers
<username> ALL=(root) NOPASSWD: /usr/sbin/openfortivpn
```

Example:

```sudoers
asepimam ALL=(root) NOPASSWD: /usr/bin/openfortivpn
```

---

# Important Notes

* Per-user sudo rules are safer than global `%sudo ALL=(ALL) NOPASSWD`
* Never edit `/etc/sudoers` directly without `visudo`
* If `NOPASSWD` is not configured, the application can still use `sudo -S` and request the sudo password
* The application automatically checks whether:

  * `openfortivpn` is installed
  * required privileges are available

---

# Logging Behavior Summary

## Normal Mode

* Dashboard displays important VPN status information
* Raw process output is hidden

## Debug Mode (`-d`)

* Raw `openfortivpn` output is written to:

```text
/tmp/openfortivpn-tui.log
```

* OTP tokens are never stored in logs

---

# Build From Source

Requires Rust stable toolchain.

```bash
git clone https://github.com/Asepimam/openfortivpn-tui.git
cd openfortivpn-tui
cargo build --release
```

Run:

```bash
./target/release/openfortivpn-tui
```

---

# License

MIT License
