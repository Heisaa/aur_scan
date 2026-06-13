use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use minisign_verify::{PublicKey, Signature};
use tempfile::NamedTempFile;

use crate::rules;

const MAX_UPDATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct UpdateOptions<'a> {
    pub url: &'a str,
    pub signature_url: &'a str,
    pub public_key: &'a str,
    pub destination: &'a Path,
    pub allow_insecure_http: bool,
}

pub fn default_ioc_path() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|path| path.join("aur-scan").join("iocs.toml"))
        .context("cannot determine user configuration directory; pass --destination")
}

pub fn update(options: &UpdateOptions<'_>) -> Result<()> {
    validate_url(options.url, options.allow_insecure_http)?;
    validate_url(options.signature_url, options.allow_insecure_http)?;

    let data = download(options.url).context("cannot download IOC data")?;
    let signature_text = String::from_utf8(download(options.signature_url)?)
        .context("IOC signature is not valid UTF-8")?;
    install_verified(
        &data,
        &signature_text,
        options.public_key,
        options.destination,
    )
}

pub fn install_verified(
    data: &[u8],
    signature_text: &str,
    public_key_text: &str,
    destination: &Path,
) -> Result<()> {
    let public_key = PublicKey::decode(public_key_text.trim())
        .or_else(|_| PublicKey::from_base64(public_key_text.trim()))
        .context("cannot decode Minisign public key")?;
    let signature =
        Signature::decode(signature_text).context("cannot decode Minisign signature")?;
    public_key
        .verify(data, &signature, false)
        .context("IOC signature verification failed")?;

    let text = std::str::from_utf8(data).context("IOC data is not valid UTF-8")?;
    rules::parse_rules(text).context("downloaded IOC data failed schema validation")?;

    let parent = destination
        .parent()
        .context("IOC destination has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("cannot create {}", parent.display()))?;
    let mut temporary =
        NamedTempFile::new_in(parent).context("cannot create temporary IOC file")?;
    std::io::Write::write_all(&mut temporary, data).context("cannot write temporary IOC file")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync temporary IOC file")?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot install {}", destination.display()))?;
    Ok(())
}

fn validate_url(url: &str, allow_insecure_http: bool) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if allow_insecure_http && (url.starts_with("http://") || url.starts_with("file://")) {
        return Ok(());
    }
    bail!("IOC update URLs must use HTTPS (development override: --allow-insecure-http)");
}

fn download(url: &str) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        let data = fs::read(path).with_context(|| format!("cannot read {path}"))?;
        if data.len() > MAX_UPDATE_BYTES {
            bail!("download exceeds {MAX_UPDATE_BYTES} byte limit");
        }
        return Ok(data);
    }
    let mut response = ureq::get(url).call().context("HTTP request failed")?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_UPDATE_BYTES as u64)
        .read_to_vec()
        .context("cannot read HTTP response")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use minisign::{KeyPair, sign};
    use tempfile::TempDir;

    use super::install_verified;

    const VALID_RULES: &str = r#"schema_version = 1
generated_at = "2026-06-13"
known_packages = []
"#;

    #[test]
    fn installs_authentic_valid_rules() {
        let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().unwrap();
        let signature = sign(None, &sk, Cursor::new(VALID_RULES), None, None).unwrap();
        let directory = TempDir::new().unwrap();
        let destination = directory.path().join("iocs.toml");

        install_verified(
            VALID_RULES.as_bytes(),
            &signature.to_string(),
            &pk.to_base64(),
            &destination,
        )
        .unwrap();

        assert_eq!(std::fs::read_to_string(destination).unwrap(), VALID_RULES);
    }

    #[test]
    fn rejects_tampered_rules() {
        let KeyPair { pk, sk } = KeyPair::generate_unencrypted_keypair().unwrap();
        let signature = sign(None, &sk, Cursor::new(VALID_RULES), None, None).unwrap();
        let directory = TempDir::new().unwrap();
        let destination = directory.path().join("iocs.toml");

        let error = install_verified(
            b"schema_version = 1\ngenerated_at = \"tampered\"\n",
            &signature.to_string(),
            &pk.to_base64(),
            &destination,
        )
        .unwrap_err();

        assert!(error.to_string().contains("signature verification"));
        assert!(!destination.exists());
    }
}
