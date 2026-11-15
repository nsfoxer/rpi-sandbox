//! Host runtime-action bridge.
//!
//! The plugin stores the host vtable handles at registration and routes
//! `UiDialog`, `SetStatus`, and message output through them.

use std::ffi::c_void;
use std::sync::Mutex;

use rpi_plugin_sdk::{
    FreeStringFn, PluginApi, RuntimeActionFn, RuntimeActionId, StbString, StbStringRef,
};
use serde_json::Value;

use crate::dialog::{DialogAction, DialogHost};

#[derive(Clone, Copy)]
struct Host {
    free_string: FreeStringFn,
    runtime_action: RuntimeActionFn,
    user_data: usize,
}

static HOST: Mutex<Option<Host>> = Mutex::new(None);

/// Store the host handles. Called once from the registration entrypoint.
pub fn install(api: &PluginApi) {
    if let Ok(mut slot) = HOST.lock() {
        *slot = Some(Host {
            free_string: api.free_string,
            runtime_action: api.runtime_action,
            user_data: api.user_data as usize,
        });
    }
}

/// Invoke one runtime action.
pub fn action(id: RuntimeActionId, args: &Value) -> Result<Value, String> {
    let host = HOST
        .lock()
        .map_err(|_| "host bridge poisoned".to_string())?
        .ok_or_else(|| "host bridge is not installed".to_string())?;
    let encoded = serde_json::to_string(args).map_err(|error| error.to_string())?;
    let mut out = StbString::empty();
    // SAFETY: `encoded` outlives the call and is valid UTF-8; `user_data` is the
    // host-provided runtime handle stored at registration; `out` is a writable,
    // initialized slot the host owns until it hands us the string.
    let rc = (host.runtime_action)(
        u32::from(id),
        StbStringRef::from_str(&encoded),
        &mut out,
        host.user_data as *mut c_void,
    );
    let text = unsafe { out.to_string_lossy() };
    // SAFETY: on return the host transferred one live allocation (or empty) to
    // us; the documented owner is the producer's `free_string`.
    unsafe { out.free_with(Some(host.free_string)) };
    if rc != 0 {
        return Err(if text.is_empty() {
            format!("runtime action {} failed with {rc}", u32::from(id))
        } else {
            text
        });
    }
    serde_json::from_str(&text).map_err(|error| format!("invalid runtime action reply: {error}"))
}

/// Publish a short footer status; an empty value clears it.
pub fn set_status(key: &str, value: &str) {
    let _ = action(
        RuntimeActionId::SetStatus,
        &serde_json::json!({"key": key, "value": value}),
    );
}

/// `UiDialog` transport used by the approval flow.
pub struct UiDialogBridge;

impl DialogHost for UiDialogBridge {
    fn dialog(&self, _action: DialogAction, args: &Value) -> Result<Value, String> {
        // The envelope already carries `op` (`open` / `poll` / `cancel`).
        action(RuntimeActionId::UiDialog, args)
    }
}
