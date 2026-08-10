const CREDENTIAL_SERVICE: &str = "cloudcord-desktop";

#[tauri::command]
fn save_refresh_token(account_id: String, token: String) -> Result<(), String> {
    keyring::Entry::new(CREDENTIAL_SERVICE, &account_id)
        .map_err(|error| error.to_string())?
        .set_password(&token)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn load_refresh_token(account_id: String) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, &account_id).map_err(|error| error.to_string())?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
fn delete_refresh_token(account_id: String) -> Result<(), String> {
    let entry = keyring::Entry::new(CREDENTIAL_SERVICE, &account_id).map_err(|error| error.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            save_refresh_token,
            load_refresh_token,
            delete_refresh_token
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CloudCord desktop client");
}
