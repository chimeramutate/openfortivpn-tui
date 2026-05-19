use crate::{
    app::{App, Focus, UiMode},
    config::VpnProfile,
};

pub fn start_new(app: &mut App) {
    app.ui_mode = UiMode::NewProfile;
    app.profile_name.clear();
    app.profile_host.clear();
    app.profile_port = "443".to_string();
    app.profile_username.clear();
    app.profile_password.clear();
    app.profile_sudo_password.clear();
    app.profile_save_password = false;
    app.profile_use_sudo_password = false;
    app.editing_profile_name = None;
    app.focus = Focus::ProfileName;
}

pub fn start_edit(app: &mut App, profile: &VpnProfile) {
    app.ui_mode = UiMode::EditProfile;
    app.editing_profile_name = Some(profile.name.clone());
    app.profile_name = profile.name.clone();
    app.profile_host = profile.host.clone();
    app.profile_port = profile.port.to_string();
    app.profile_username = profile.username.clone();
    app.profile_password = profile.password.clone();
    app.profile_sudo_password = profile.sudo_password.clone();
    app.profile_save_password = profile.save_password;
    app.profile_use_sudo_password = profile.use_sudo_password;
    app.focus = Focus::ProfileName;
}
