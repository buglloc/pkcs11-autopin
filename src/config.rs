use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    pin_cache: parking_lot::RwLock<HashMap<String, Option<String>>>,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_file(DEFAULT_CONFIG_PATH)
    }

    pub fn from_file<P: AsRef<Path>>(filepath: P) -> Result<Self, Box<dyn std::error::Error>> {
        let filepath = filepath.as_ref();

        let config_file: ConfigFile = if filepath.exists() {
            let content = fs::read_to_string(filepath)?;
            serde_yaml::from_str(&content)?
        } else {
            ConfigFile {
                debug: false,
                backend: None,
                pins_dir: None,
            }
        };

        Ok(Config {
            debug: config_file.debug,
            backend_path: config_file.backend.unwrap_or_else(|| DEFAULT_BACKEND.to_string()),
            pins_dir: PathBuf::from(config_file.pins_dir.unwrap_or_else(|| DEFAULT_PINS_DIR.to_string())),
            pin_cache: parking_lot::RwLock::new(HashMap::new()),
        })
    }


    pub fn get_pin_for_label(&self, label: &str) -> Option<String> {
        let token_label = Self::sanitize_label(label);

        {
            let cache = self.pin_cache.read();
            if let Some(cached) = cache.get(&token_label) {
                return cached.clone();
            }
        }

        let pin = self.read_pin_file(&token_label);

        {
            let mut cache = self.pin_cache.write();
            cache.insert(token_label, pin.clone());
        }

        pin
    }

    fn read_pin_file(&self, token_label: &str) -> Option<String> {
        let pin_path = self.pins_dir.join(token_label);
        let pin = fs::read_to_string(&pin_path).ok()?;
        let pin = pin.trim().to_string();

        if pin.is_empty() {
            None
        } else {
            Some(pin)
        }
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
            pin_cache: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}
