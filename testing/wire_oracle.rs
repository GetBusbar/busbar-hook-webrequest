// SPDX-License-Identifier: Apache-2.0
//! Independent expected-wire oracle for comparison with the production SDK projection writer.

const ALIAS: &str = "webrequest";

/// The POST envelope for a per-request op: the engine's opaque `payload` projection (BORROWED, not
/// cloned) with an `op` discriminator merged in, mirroring the old webhook wire. The projection is
/// carried through UNCHANGED, so any opt-in `prompt`/`user` keys the CORE granted ride straight through.
struct Envelope<'a> {
    op: &'a str,
    payload: &'a serde_json::Value,
}

impl serde::Serialize for Envelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match self.payload {
            serde_json::Value::Object(m) => {
                let mut map = serializer.serialize_map(Some(m.len() + 1))?;

                for (k, v) in m.iter().filter(|(k, _)| k.as_str() != "op") {
                    map.serialize_entry(k, v)?;
                }
                map.serialize_entry("op", self.op)?;
                map.end()
            }

            other => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("payload", other)?;
                map.serialize_entry("op", self.op)?;
                map.end()
            }
        }
    }
}

/// The JSON body for `op` over `payload`.
pub fn envelope(op: &str, payload: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&Envelope { op, payload })
        .map_err(|e| format!("{ALIAS}: failed to serialize op envelope: {e}"))
}
