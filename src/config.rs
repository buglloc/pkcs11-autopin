use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEFAULT_BACKEND: &str = "/usr/lib64/pkcs11/libtpm2_pkcs11.so.0.0.0";
const DEFAULT_CONFIG_PATH: &str = "/etc/pkcs11-autopin.yaml";
const DEFAULT_PINS_DIR: &str = "/etc/pkcs11-autopin.pins";

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub debug: bool,
    pub backend: Option<String>,
    pub pins_dir: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub debug: bool,
    pub backend_path: String,
    pins_dir: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_file(DEFAULT_CONFIG_PATH)
    }

    pub fn from_file<P: AsRef<Path>>(filepath: P) -> Result<Self, Box<dyn std::error::Error>> {
        let filepath = filepath.as_ref();

        let config_file: ConfigFile = if filepath.exists() {
            let content = fs::read_to_string(filepath)?;
            noyalib::from_str(&content)?
        } else {
            ConfigFile {
                debug: false,
                backend: None,
                pins_dir: None,
            }
        };

        Ok(Config {
            debug: config_file.debug,
            backend_path: config_file
                .backend
                .unwrap_or_else(|| DEFAULT_BACKEND.to_string()),
            pins_dir: PathBuf::from(
                config_file
                    .pins_dir
                    .unwrap_or_else(|| DEFAULT_PINS_DIR.to_string()),
            ),
        })
    }

    pub fn get_pin_for_label(&self, label: &str) -> Option<Zeroizing<Vec<u8>>> {
        let token_label = Self::sanitize_label(label);
        self.read_pin_file(&token_label)
    }

    fn read_pin_file(&self, token_label: &str) -> Option<Zeroizing<Vec<u8>>> {
        let pin_path = self.pins_dir.join(token_label);
        let mut pin = Zeroizing::new(fs::read(&pin_path).ok()?);
        Self::trim_ascii_whitespace(&mut pin);

        if pin.is_empty() {
            None
        } else {
            Some(pin)
        }
    }

    fn trim_ascii_whitespace(pin: &mut Vec<u8>) {
        let leading = pin.len() - pin.trim_ascii_start().len();
        pin.drain(..leading);
        pin.truncate(pin.trim_ascii_end().len());
    }

    fn sanitize_label(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            debug: false,
            backend_path: DEFAULT_BACKEND.to_string(),
            pins_dir: PathBuf::from(DEFAULT_PINS_DIR),
        }
    }
}
