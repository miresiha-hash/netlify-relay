//! The outbound wire: [`BaleTextWire`] adapts the real Bale
//! signaling client to the [`TextWire`] trait the tunnel sends
//! through. Pure signaling glue — no cfg gates; `bale-signaling`
//! builds on every target.

use bale_signaling::BaleSignaling;
use lk_signaling::PeerId;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{TextWire, WireError};

// ── outbound half: Bale signaling as a TextWire ────────────────

/// [`TextWire`] over the real Bale signaling client.
///
/// `send_text_message` is inherent on `BaleSignaling` (not on the
/// `Signaling` trait) and it resolves `PeerId` to a uid itself, so
/// no extra conversion happens here.
pub struct BaleTextWire {
    signaling: Arc<BaleSignaling>,
    peer:      PeerId,
}

impl BaleTextWire {
    pub fn new(signaling: Arc<BaleSignaling>, peer: PeerId) -> Self {
        Self { signaling, peer }
    }
}

#[async_trait]
impl TextWire for BaleTextWire {
    async fn send(&self, text: &str) -> Result<(), WireError> {
        match self.signaling.send_text_message(&self.peer, text).await {
            Ok(_) => Ok(()),
            // The pacer has already spent this slot's budget, so
            // there is nothing to retry inline — the tunnel's 15 s
            // retransmit is what recovers it.
            Err(e) => {
                let s = e.to_string();
                // Bale refuses a message over the per-account bucket
                // with `RPC error code=8 … user_rate_limited`. That
                // used to arrive here as `Failed`, so the tunnel's
                // 2 s/50-retry backoff (`run_sender`'s RateLimited
                // arm) never once ran and the `rate_limited` stat
                // sat at 0 no matter how hard we pushed. Typed
                // error instead, detected on the one string the
                // RPC layer actually renders.
                if s.contains("user_rate_limited") {
                    Err(WireError::RateLimited)
                } else {
                    Err(WireError::Failed(s))
                }
            }
        }
    }
}
