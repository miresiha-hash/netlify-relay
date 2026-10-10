//! Carrier selection — *which* transport carries tunnel bytes.
//!
//! This is orthogonal to `config::mode` (`client` / `server`),
//! which decides *who calls whom*. The carrier decides what the
//! bytes ride on once a session exists.
//!
//!   - [`CarrierKind::Voice`] — the LiveKit WebRTC / Opus path
//!     (`lktunnel`'s `Engine`). This is the original product and
//!     still the carrier that carries calls and SOCKS5.
//!   - [`CarrierKind::Text`]  — chunked tunnel frames over Bale
//!     text messages. **Implemented**: [`crate::text_client`]
//!     moves real IP packets over `send_text_message` with no
//!     call, no ReliabilitySocket and no LiveKit dependency.
//!   - [`CarrierKind::File`]  — the Files service (upload /
//!     download, HTTP Range). Protocol surface proven; bulk
//!     path (≈0.74 MB/s up, ≈9.5 MB/s down on the VPS).
//!   - [`CarrierKind::God`]   — automatic: probe every available
//!     carrier, send control-plane on the lowest-latency one and
//!     bulk on the highest-throughput one, fail over mid-session
//!     when a carrier dies. Sits *on top of* the others via the
//!     same trait — not a fourth transport.
//!
//! An unimplemented carrier degrades to Voice with a loud log
//! rather than refusing to connect: the selector is live now, the
//! transports fill in behind it.

use serde::{Deserialize, Serialize};

/// One selectable transport. Serialized verbatim into
/// `.bale-vpn_config.json` as `"carrier"` and echoed over
/// `/config` as `carrier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CarrierKind {
    /// LiveKit WebRTC + Opus (the shipped product).
    #[default]
    Voice,
    /// Chunked frames over Bale text messages.
    Text,
    /// Files service (upload / download with Range).
    File,
    /// Automatic multiplexer over all of the above.
    God,
}

impl CarrierKind {
    /// Parse a config/CLI/UI string. Unknown values → `None` so
    /// the caller can reject them at the boundary instead of
    /// silently defaulting (a typo'd `--carrier tex` should not
    /// quietly become Voice).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "voice" | "call" | "rtc" => Some(Self::Voice),
            "text"                   => Some(Self::Text),
            "file"                   => Some(Self::File),
            "god" | "auto"           => Some(Self::God),
            _                        => None,
        }
    }

    /// Stable wire / log form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Voice => "voice",
            Self::Text  => "text",
            Self::File  => "file",
            Self::God   => "god",
        }
    }

    /// The carrier to actually run when this one is selected.
    ///
    /// * `Text` → `Text`: **a real transport.** IP packets ride
    ///   Bale text messages end-to-end ([`crate::text_client`]),
    ///   with no call and no ReliabilitySocket. This is the one
    ///   mode that survives the SFU being unreachable.
    /// * `File` → `Voice`: the Files service is proven at the
    ///   protocol level but has no byte path in this client yet.
    /// * `God` → `Voice`: the cluster engine owns this policy;
    ///   until it speaks, God behaves like Voice.
    ///
    /// `is_available()` reads this, so selecting Text stops
    /// logging a fallback and starts a Text session instead.
    pub fn effective(self) -> CarrierKind {
        match self {
            CarrierKind::Text => CarrierKind::Text,
            CarrierKind::Voice | CarrierKind::File | CarrierKind::God => CarrierKind::Voice,
        }
    }

    /// True when the user's pick runs as-is (no fallback).
    pub fn is_available(self) -> bool {
        self.effective() == self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_case_insensitive_and_tolerates_aliases() {
        assert_eq!(CarrierKind::parse("Voice"), Some(CarrierKind::Voice));
        assert_eq!(CarrierKind::parse(" CALL "), Some(CarrierKind::Voice));
        assert_eq!(CarrierKind::parse("rtc"),    Some(CarrierKind::Voice));
        assert_eq!(CarrierKind::parse("text"),   Some(CarrierKind::Text));
        assert_eq!(CarrierKind::parse("file"),   Some(CarrierKind::File));
        assert_eq!(CarrierKind::parse("god"),    Some(CarrierKind::God));
        assert_eq!(CarrierKind::parse("auto"),   Some(CarrierKind::God));
    }

    #[test]
    fn parse_rejects_unknown_values() {
        assert_eq!(CarrierKind::parse("tex"),    None);
        assert_eq!(CarrierKind::parse(""),       None);
        assert_eq!(CarrierKind::parse("quic"),   None);
    }

    #[test]
    fn round_trips_through_serde() {
        for k in [
            CarrierKind::Voice, CarrierKind::Text,
            CarrierKind::File,  CarrierKind::God,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
            let back: CarrierKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, k);
        }
    }

    #[test]
    fn default_is_voice() {
        // Existing installs have no "carrier" key; they must land
        // on the carrier that shipped with them.
        assert_eq!(CarrierKind::default(), CarrierKind::Voice);
        let cfg: CarrierKind = serde_json::from_str("\"voice\"").unwrap();
        assert_eq!(cfg, CarrierKind::Voice);
    }

    #[test]
    fn text_is_live_and_the_rest_still_fall_back_to_voice() {
        // Text has a byte path now — it must NOT be normalised
        // away to Voice, or the user's pick silently vanishes.
        assert_eq!(CarrierKind::Text.effective(), CarrierKind::Text);
        assert!(CarrierKind::Text.is_available());
        // Still-unimplemented carriers degrade loudly to Voice.
        assert_eq!(CarrierKind::File.effective(), CarrierKind::Voice);
        assert_eq!(CarrierKind::God.effective(),  CarrierKind::Voice);
        assert!(!CarrierKind::File.is_available());
        assert!(!CarrierKind::God.is_available());
        assert_eq!(CarrierKind::Voice.effective(), CarrierKind::Voice);
        assert!(CarrierKind::Voice.is_available());
    }

    #[test]
    fn config_file_default_round_trips_partial_json() {
        // A pre-carrier config file must still deserialize.
        #[derive(serde::Deserialize)]
        struct HasDefault {
            #[serde(default)]
            carrier: CarrierKind,
        }
        let old: HasDefault = serde_json::from_str("{}").unwrap();
        assert_eq!(old.carrier, CarrierKind::Voice);
    }
}
