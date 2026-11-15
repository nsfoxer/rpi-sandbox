//! `rpi-sandbox` extension.
//!
//! Phase 0 only reserves the crate and verifies that it links against the
//! public plugin SDK. Phase 2 adds the `ToolCall` veto, `UiDialog` approvals,
//! configuration, audit, `/sandbox`, and footer status.
//!
//! The extension cannot create a kernel boundary on its own: that only happens
//! in the launcher before `exec`. Without `RPI_SANDBOX_ACTIVE` it must report
//! "not isolated" and may only perform advisory gating.

/// Crate name used in diagnostics.
pub const CRATE_NAME: &str = "rpi-sandbox-extension";

#[cfg(test)]
mod tests {
    #[test]
    fn links_against_the_public_plugin_sdk() {
        assert_eq!(rpi_plugin_sdk::HOST_NAME, "rpi");
    }

    #[test]
    fn shares_the_core_protocol_version() {
        assert_eq!(rpi_sandbox_core::PROTOCOL_VERSION, 1);
    }
}
