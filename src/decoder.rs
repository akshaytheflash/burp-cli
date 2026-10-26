//! Decoder/encoder toolbox, including JWT helpers and smart decoding.

use crate::util::{b64_decode, b64_encode, b64url_decode, b64url_encode, to_text};
use anyhow::{anyhow, bail, Context, Result};
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io::{Read, Write};

pub const CODECS: &[&str] = &[
    "base64",
    "base64url",
    "hex",
    "url",
    "html",
    "unicode",
    "gzip",
    "deflate",
    "rot13",
    "binary",
    "md5",
    "sha1",
    "sha256",
    "jwt",
];

pub fn codec_help() -> String {
    CODECS.join(", ")
}

fn text(data: &[u8]) -> Result<&str> {
    std::str::from_utf8(data).map_err(|_| anyhow!("codec requires UTF-8 input"))
}

pub fn transform(data: &[u8], codecs: &[String], encode: bool) -> Result<Vec<u8>> {
    let mut current = data.to_vec();
    for codec in codecs {
        current = apply(codec, &current, encode)?;
    }
    Ok(current)
}

fn apply(codec: &str, data: &[u8], encode: bool) -> Result<Vec<u8>> {
    let name = codec.to_ascii_lowercase();
    let name = name.strip_prefix("encode:").unwrap_or(&name);
    match name {
        "base64" => {
            if encode {
                Ok(b64_encode(data).into_bytes())
            } else {
                Ok(b64_decode(text(data)?)?)
            }
        }
        "base64url" => {
            if encode {
                Ok(b64url_encode(data).into_bytes())
            } else {
                Ok(b64url_decode(text(data)?)?)
            }
        }
        "hex" => {
            if encode {
                Ok(hex::encode(data).into_bytes())
            } else {
                let text = text(data)?.trim();
                hex::decode(text).map_err(|e| anyhow!("invalid hex: {e}"))
            }
        }
        "url" => {
            if encode {
                let encoded = percent_encoding::utf8_percent_encode(
                    text(data)?,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                Ok(encoded.to_string().into_bytes())
            } else {
                let decoded = percent_encoding::percent_decode_str(text(data)?)
                    .decode_utf8()
                    .context("percent-decoded data is not UTF-8")?;
                Ok(decoded.into_owned().into_bytes())
            }
        }
        "html" => {
            if encode {
                Ok(crate::util::html_escape(text(data)?).into_bytes())
            } else {
                Ok(html_decode(text(data)?).into_bytes())
            }
        }
        "unicode" => {
            if encode {
                Ok(unicode_encode(text(data)?).into_bytes())
            } else {
                Ok(unicode_decode(text(data)?)?.into_bytes())
            }
        }
        "gzip" => {
            if encode {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            } else {
                let mut decoder = GzDecoder::new(data);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out).context("invalid gzip data")?;
                Ok(out)
            }
        }
        "deflate" | "zlib" => {
            if encode {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            } else {
                let mut decoder = ZlibDecoder::new(data);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out).context("invalid zlib data")?;
                Ok(out)
            }
        }
        "rot13" => {
            let out = text(data)?
                .chars()
                .map(|c| match c {
                    'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                    'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                    _ => c,
                })
                .collect::<String>();
            Ok(out.into_bytes())
        }
        "binary" => {
            if encode {
                Ok(data
                    .iter()
                    .map(|b| format!("{b:08b}"))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .into_bytes())
            } else {
                let bits: String = text(data)?
                    .chars()
                    .filter(|c| *c == '0' || *c == '1')
                    .collect();
                if bits.len() % 8 != 0 {
                    bail!("bit length is not a multiple of 8");
                }
                let mut out = Vec::new();
                for chunk in bits.as_bytes().chunks(8) {
                    let s = std::str::from_utf8(chunk)?;
                    out.push(u8::from_str_radix(s, 2)?);
                }
                Ok(out)
            }
        }
        "md5" => {
            if !encode {
                bail!("md5 is a one-way hash");
            }
            use md5::Md5;
            let mut hasher = Md5::new();
            hasher.update(data);
            Ok(hex::encode(hasher.finalize()).into_bytes())
        }
        "sha1" => {
            if !encode {
                bail!("sha1 is a one-way hash");
            }
            let mut hasher = Sha1::new();
            hasher.update(data);
            Ok(hex::encode(hasher.finalize()).into_bytes())
        }
        "sha256" => {
            if !encode {
                bail!("sha256 is a one-way hash");
            }
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hex::encode(hasher.finalize()).into_bytes())
        }
        "jwt" => {
            if encode {
                bail!("use `burpcli decoder jwt sign` for JWT encoding");
            }
            let jwt = decode_jwt(text(data)?)?;
            Ok(jwt.pretty().into_bytes())
        }
        other => bail!("unknown codec '{other}' (available: {})", codec_help()),
    }
}

fn html_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        if let Some(end) = after.find(';') {
            let entity = &after[1..end];
            if let Some(decoded) = decode_entity(entity) {
                out.push(decoded);
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push('&');
        rest = &after[1..];
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    let named = match entity.to_ascii_lowercase().as_str() {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" | "#39" => '\'',
        "nbsp" => '\u{00a0}',
        "copy" => '©',
        "reg" => '®',
        "hellip" => '…',
        "mdash" => '—',
        "ndash" => '–',
        _ => {
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
            }
            if let Some(dec) = entity.strip_prefix('#') {
                return dec.parse::<u32>().ok().and_then(char::from_u32);
            }
            return None;
        }
    };
    Some(named)
}

fn unicode_encode(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        let code = ch as u32;
        if code > 0xFFFF {
            let code = code - 0x10000;
            let high = 0xD800 + (code >> 10);
            let low = 0xDC00 + (code & 0x3FF);
            out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
        } else if ch.is_ascii_graphic() || ch == ' ' || ch == '\n' || ch == '\t' {
            out.push(ch);
        } else {
            out.push_str(&format!("\\u{code:04x}"));
        }
    }
    out
}

fn unicode_decode(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.peek().copied() {
            Some('u') => {
                chars.next();
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut hex = String::new();
                    for c in chars.by_ref() {
                        if c == '}' {
                            break;
                        }
                        hex.push(c);
                    }
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                    }
                } else {
                    let mut hex = String::new();
                    for _ in 0..4 {
                        if let Some(c) = chars.next() {
                            hex.push(c);
                        }
                    }
                    if let Ok(code) = u16::from_str_radix(&hex, 16) {
                        if (0xD800..0xDC00).contains(&code) {
                            // Attempt to read a low surrogate.
                            if chars.peek() == Some(&'\\') {
                                let mut clone = chars.clone();
                                clone.next();
                                if clone.peek() == Some(&'u') {
                                    clone.next();
                                    let mut low_hex = String::new();
                                    for _ in 0..4 {
                                        if let Some(c) = clone.next() {
                                            low_hex.push(c);
                                        }
                                    }
                                    if let Ok(low) = u16::from_str_radix(&low_hex, 16) {
                                        if (0xDC00..0xE000).contains(&low) {
                                            chars = clone;
                                            let code = 0x10000
                                                + (((code - 0xD800) as u32) << 10)
                                                + (low - 0xDC00) as u32;
                                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        out.push(char::from_u32(code as u32).unwrap_or('\u{FFFD}'));
                    }
                }
            }
            Some('x') => {
                chars.next();
                let mut hex = String::new();
                for _ in 0..2 {
                    if let Some(c) = chars.next() {
                        hex.push(c);
                    }
                }
                if let Ok(code) = u8::from_str_radix(&hex, 16) {
                    out.push(code as char);
                }
            }
            _ => out.push('\\'),
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct JwtParts {
    pub header: Value,
    pub payload: Value,
    pub signature: Vec<u8>,
    pub signing_input: String,
}

impl JwtParts {
    pub fn pretty(&self) -> String {
        format!(
            "Header:\n{}\n\nPayload:\n{}\n\nSignature: {}",
            serde_json::to_string_pretty(&self.header).unwrap_or_default(),
            serde_json::to_string_pretty(&self.payload).unwrap_or_default(),
            hex::encode(&self.signature)
        )
    }

    pub fn algorithm(&self) -> Option<&str> {
        self.header.get("alg").and_then(Value::as_str)
    }
}

pub fn decode_jwt(token: &str) -> Result<JwtParts> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        bail!("a JWT must have three dot-separated parts");
    }
    let header_bytes = b64url_decode(parts[0]).context("invalid JWT header")?;
    let payload_bytes = b64url_decode(parts[1]).context("invalid JWT payload")?;
    let header: Value = serde_json::from_slice(&header_bytes).context("JWT header is not JSON")?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).context("JWT payload is not JSON")?;
    let signature = b64url_decode(parts[2]).unwrap_or_default();
    Ok(JwtParts {
        header,
        payload,
        signature,
        signing_input: format!("{}.{}", parts[0], parts[1]),
    })
}

pub fn jwt_sign(header: &Value, payload: &Value, secret: &str, alg: &str) -> Result<String> {
    let header_b64 = b64url_encode(&serde_json::to_vec(header)?);
    let payload_b64 = b64url_encode(&serde_json::to_vec(payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let alg = alg.to_ascii_uppercase();
    let signature = match alg.as_str() {
        "HS256" => hmac_sign::<Hmac<Sha256>>(&signing_input, secret)?,
        "HS384" => hmac_sign::<Hmac<Sha384>>(&signing_input, secret)?,
        "HS512" => hmac_sign::<Hmac<Sha512>>(&signing_input, secret)?,
        "NONE" => Vec::new(),
        other => bail!("unsupported JWT algorithm '{other}' (use HS256, HS384, HS512 or none)"),
    };
    Ok(format!("{signing_input}.{}", b64url_encode(&signature)))
}

fn hmac_sign<M: Mac + hmac::digest::KeyInit>(input: &str, secret: &str) -> Result<Vec<u8>> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow!("invalid HMAC key"))?;
    mac.update(input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Rewrite a JWT with `alg: none` and an empty signature.
pub fn jwt_none(token: &str) -> Result<String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        bail!("a JWT must have three dot-separated parts");
    }
    let mut header: Value = serde_json::from_slice(&b64url_decode(parts[0])?)?;
    if let Some(object) = header.as_object_mut() {
        object.insert("alg".into(), Value::String("none".into()));
    }
    let header_b64 = b64url_encode(&serde_json::to_vec(&header)?);
    Ok(format!("{header_b64}.{}.", parts[1]))
}

pub fn identify(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim();
    if trimmed.split('.').count() == 3 && trimmed.starts_with("eyJ") {
        found.push("JWT".to_string());
    }
    if trimmed.starts_with('{') && serde_json::from_str::<Value>(trimmed).is_ok() {
        found.push("JSON".to_string());
    }
    if trimmed.starts_with("gzip") || data.starts_with(&[0x1f, 0x8b]) {
        found.push("gzip".to_string());
    }
    if data.len() > 2 && data[0] == 0x78 {
        found.push("zlib/deflate (possible)".to_string());
    }
    if trimmed.contains('%')
        && regex::Regex::new(r"%[0-9A-Fa-f]{2}")
            .unwrap()
            .is_match(trimmed)
    {
        found.push("URL-encoded".to_string());
    }
    if trimmed.contains('&')
        && regex::Regex::new(r"&(#x?[0-9A-Fa-f]+|\w+);")
            .unwrap()
            .is_match(trimmed)
    {
        found.push("HTML entities".to_string());
    }
    if trimmed.len() >= 8
        && trimmed.len() % 2 == 0
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        found.push("hex".to_string());
    }
    if trimmed.len() >= 8
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c))
    {
        if let Ok(decoded) = b64_decode(trimmed) {
            if printable_ratio(&decoded) > 0.85 {
                found.push("base64".to_string());
            }
        }
        if let Ok(decoded) = b64url_decode(trimmed) {
            if printable_ratio(&decoded) > 0.85 && !found.contains(&"base64".to_string()) {
                found.push("base64url".to_string());
            }
        }
    }
    match trimmed.len() {
        32 if trimmed.chars().all(|c| c.is_ascii_hexdigit()) => found.push("md5 (possible)".into()),
        40 if trimmed.chars().all(|c| c.is_ascii_hexdigit()) => {
            found.push("sha1 (possible)".into())
        }
        64 if trimmed.chars().all(|c| c.is_ascii_hexdigit()) => {
            found.push("sha256 (possible)".into())
        }
        _ => {}
    }
    found
}

pub fn smart_decode(data: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut current = data.to_vec();
    let mut applied = Vec::new();
    let percent_re = regex::Regex::new(r"%[0-9A-Fa-f]{2}").expect("valid percent regex");
    for _ in 0..5 {
        let text = match std::str::from_utf8(&current) {
            Ok(t) => t.trim().to_string(),
            Err(_) => String::new(),
        };
        if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) {
            break;
        }
        if !text.is_empty()
            && (text.len() % 4 == 0 || text.ends_with('='))
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c))
        {
            if let Ok(decoded) = b64_decode(&text) {
                if printable_ratio(&decoded) > 0.85 && decoded != current {
                    current = decoded;
                    applied.push("base64".into());
                    continue;
                }
            }
        }
        if !text.is_empty() && percent_re.is_match(&text) {
            if let Ok(decoded) = percent_encoding::percent_decode_str(&text).decode_utf8() {
                if decoded.as_bytes() != current {
                    current = decoded.into_owned().into_bytes();
                    applied.push("url".into());
                    continue;
                }
            }
        }
        if text.len() >= 4 && text.len() % 2 == 0 && text.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(decoded) = hex::decode(&text) {
                if printable_ratio(&decoded) > 0.85 {
                    current = decoded;
                    applied.push("hex".into());
                    continue;
                }
            }
        }
        if text.contains('&') && text.contains(';') {
            let decoded = html_decode(&text);
            if decoded != text {
                current = decoded.into_bytes();
                applied.push("html".into());
                continue;
            }
        }
        if current.starts_with(&[0x1f, 0x8b]) {
            if let Ok(decoded) = apply("gzip", &current, false) {
                current = decoded;
                applied.push("gzip".into());
                continue;
            }
        }
        break;
    }
    (current, applied)
}

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|b| {
            b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\r' || **b == b'\t'
        })
        .count();
    printable as f64 / data.len() as f64
}

pub fn display(data: &[u8]) -> String {
    to_text(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for codec in [
            "base64",
            "base64url",
            "hex",
            "url",
            "html",
            "unicode",
            "gzip",
            "deflate",
            "rot13",
            "binary",
        ] {
            let input = "Hello, world! 123 & <tag> \u{1f600}".as_bytes();
            let encoded = apply(codec, input, true).unwrap();
            let decoded = apply(codec, &encoded, false).unwrap();
            assert_eq!(decoded, input, "codec {codec} failed");
        }
    }

    #[test]
    fn hashes() {
        let md5 = transform(b"abc", &["md5".into()], true).unwrap();
        assert_eq!(
            String::from_utf8(md5).unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        let sha256 = transform(b"abc", &["sha256".into()], true).unwrap();
        assert_eq!(
            String::from_utf8(sha256).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn jwt_roundtrip() {
        let header = serde_json::json!({"alg":"HS256","typ":"JWT"});
        let payload = serde_json::json!({"sub":"1234","admin":true});
        let token = jwt_sign(&header, &payload, "secret", "HS256").unwrap();
        let decoded = decode_jwt(&token).unwrap();
        assert_eq!(decoded.algorithm(), Some("HS256"));
        assert_eq!(decoded.payload["sub"], "1234");
        let none = jwt_none(&token).unwrap();
        assert!(none.ends_with('.'));
        assert_eq!(decode_jwt(&none).unwrap().algorithm(), Some("none"));
    }

    #[test]
    fn identification() {
        let ids = identify(b"SGVsbG8sIHdvcmxkIQ==");
        assert!(ids.contains(&"base64".to_string()));
        assert!(identify(b"{\"a\":1}").contains(&"JSON".to_string()));
        assert!(identify(b"%3Cscript%3E").contains(&"URL-encoded".to_string()));
    }

    #[test]
    fn smart_chain() {
        let inner = b"hello";
        let encoded = b64_encode(b"%68%65%6c%6c%6f");
        let (decoded, applied) = smart_decode(encoded.as_bytes());
        assert_eq!(decoded, inner);
        assert!(applied.len() >= 2);
    }

    #[test]
    fn unicode_surrogates() {
        let encoded = unicode_encode("hi \u{1f600}");
        assert!(encoded.contains("\\ud83d"));
        assert_eq!(unicode_decode(&encoded).unwrap(), "hi \u{1f600}");
    }
}
