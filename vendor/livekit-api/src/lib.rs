// Copyright 2025 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "access-token")]
pub mod access_token;

#[cfg(any(feature = "services-tokio", feature = "services-async"))]
pub mod services;

#[cfg(any(
    feature = "signal-client-tokio",
    feature = "signal-client-async",
    feature = "signal-client-dispatcher"
))]
pub mod signal_client;

#[cfg(any(
    feature = "signal-client-tokio",
    feature = "signal-client-async",
    feature = "signal-client-dispatcher",
    feature = "services-tokio",
    feature = "services-async"
))]
mod http_client;

#[cfg(feature = "webhooks")]
pub mod webhooks;

#[allow(dead_code)]
pub(crate) fn get_env_keys() -> Result<(String, String), std::env::VarError> {
    let api_key = std::env::var("LIVEKIT_API_KEY")?;
    let api_secret = std::env::var("LIVEKIT_API_SECRET")?;
    Ok((api_key, api_secret))
}


// Full browser User-Agent used on every HTTP/WebSocket request we make
// to Bale. Picked for the device this binary is built for (a real
// web.bale.ai visitor), and matched to the current Chrome stable
// release — bump whenever Chrome majors move. `BROWSER_UA` is the
// single source of truth: bale-signaling keeps its own copy because it
// cannot depend on this crate.
#[cfg(target_os = "android")]
pub const BROWSER_UA: &str = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.8078.25 Mobile Safari/537.36";
#[cfg(not(target_os = "android"))]
pub const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.8078.13 Safari/537.36";
