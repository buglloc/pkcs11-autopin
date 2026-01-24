use crate::config::Config;
use crate::pkcs11_types::*;
use libloading::{Library, Symbol};
use log::{debug, warn};
use parking_lot::RwLock;
use std::collections::HashMap;

pub struct Backend {
    _library: Library,
    config: Config,
    function_list: *mut CK_FUNCTION_LIST,
    /// Maps slot IDs to token labels for auto-login
    slot_to_label: RwLock<HashMap<CK_SLOT_ID, String>>,
}

unsafe impl Send for Backend {}
unsafe impl Sync for Backend {}

macro_rules! proxy_method {
    ($name:ident, $field:ident $(, $arg:ident : $ty:ty)*) => {
        pub fn $name(&self, $($arg: $ty),*) -> CK_RV {
            match self.funcs().$field {
                Some(f) => unsafe { f($($arg),*) },
                None => CKR_FUNCTION_NOT_SUPPORTED,
            }
        }
    };
}

impl Backend {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        debug!("Loading backend library: {}", config.backend_path);

        let library = unsafe { Library::new(&config.backend_path)? };
        let get_function_list: Symbol<CK_C_GetFunctionList> =
            unsafe { library.get(b"C_GetFunctionList\0")? };

        let mut function_list: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        let rv = unsafe { get_function_list(&mut function_list) };
        if rv != CKR_OK {
            return Err(format!("C_GetFunctionList failed with {}", rv).into());
        }
        if function_list.is_null() {
            return Err("C_GetFunctionList returned null".into());
        }

        Ok(Backend {
            _library: library,
            config,
            function_list,
            slot_to_label: RwLock::new(HashMap::new()),
        })
    }

    #[inline]
    fn funcs(&self) -> &CK_FUNCTION_LIST {
        unsafe { &*self.function_list }
    }

    proxy_method!(initialize, C_Initialize, init_args: CK_VOID_PTR);
    proxy_method!(finalize, C_Finalize, reserved: CK_VOID_PTR);
    proxy_method!(get_info, C_GetInfo, info: CK_INFO_PTR);
    proxy_method!(get_slot_list, C_GetSlotList, token_present: CK_BBOOL, slot_list: CK_SLOT_ID_PTR, count: CK_ULONG_PTR);
    proxy_method!(get_slot_info, C_GetSlotInfo, slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR);
    proxy_method!(get_mechanism_list, C_GetMechanismList, slot_id: CK_SLOT_ID, mechanism_list: CK_MECHANISM_TYPE_PTR, count: CK_ULONG_PTR);
    proxy_method!(get_mechanism_info, C_GetMechanismInfo, slot_id: CK_SLOT_ID, mech_type: CK_MECHANISM_TYPE, info: CK_MECHANISM_INFO_PTR);
    proxy_method!(init_token, C_InitToken, slot_id: CK_SLOT_ID, pin: CK_UTF8CHAR_PTR, pin_len: CK_ULONG, label: CK_UTF8CHAR_PTR);
    proxy_method!(init_pin, C_InitPIN, session: CK_SESSION_HANDLE, pin: CK_UTF8CHAR_PTR, pin_len: CK_ULONG);
    proxy_method!(set_pin, C_SetPIN, session: CK_SESSION_HANDLE, old_pin: CK_UTF8CHAR_PTR, old_len: CK_ULONG, new_pin: CK_UTF8CHAR_PTR, new_len: CK_ULONG);
    proxy_method!(close_session, C_CloseSession, session: CK_SESSION_HANDLE);
    proxy_method!(close_all_sessions, C_CloseAllSessions, slot_id: CK_SLOT_ID);
    proxy_method!(get_session_info, C_GetSessionInfo, session: CK_SESSION_HANDLE, info: CK_SESSION_INFO_PTR);
    proxy_method!(get_operation_state, C_GetOperationState, session: CK_SESSION_HANDLE, operation_state: CK_BYTE_PTR, operation_state_len: CK_ULONG_PTR);
    proxy_method!(set_operation_state, C_SetOperationState, session: CK_SESSION_HANDLE, operation_state: CK_BYTE_PTR, operation_state_len: CK_ULONG, encryption_key: CK_OBJECT_HANDLE, authentication_key: CK_OBJECT_HANDLE);
    proxy_method!(login, C_Login, session: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: CK_UTF8CHAR_PTR, pin_len: CK_ULONG);
    proxy_method!(logout, C_Logout, session: CK_SESSION_HANDLE);
    proxy_method!(create_object, C_CreateObject, session: CK_SESSION_HANDLE, template: CK_ATTRIBUTE_PTR, count: CK_ULONG, object: CK_OBJECT_HANDLE_PTR);
    proxy_method!(copy_object, C_CopyObject, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: CK_ATTRIBUTE_PTR, count: CK_ULONG, new_object: CK_OBJECT_HANDLE_PTR);
    proxy_method!(destroy_object, C_DestroyObject, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE);
    proxy_method!(get_object_size, C_GetObjectSize, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, size: CK_ULONG_PTR);
    proxy_method!(get_attribute_value, C_GetAttributeValue, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: CK_ATTRIBUTE_PTR, count: CK_ULONG);
    proxy_method!(set_attribute_value, C_SetAttributeValue, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: CK_ATTRIBUTE_PTR, count: CK_ULONG);
    proxy_method!(find_objects_init, C_FindObjectsInit, session: CK_SESSION_HANDLE, template: CK_ATTRIBUTE_PTR, count: CK_ULONG);
    proxy_method!(find_objects, C_FindObjects, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE_PTR, max_object_count: CK_ULONG, object_count: CK_ULONG_PTR);
    proxy_method!(find_objects_final, C_FindObjectsFinal, session: CK_SESSION_HANDLE);
    proxy_method!(encrypt_init, C_EncryptInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(encrypt, C_Encrypt, session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, data_len: CK_ULONG, encrypted_data: CK_BYTE_PTR, encrypted_data_len: CK_ULONG_PTR);
    proxy_method!(encrypt_update, C_EncryptUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG_PTR);
    proxy_method!(encrypt_final, C_EncryptFinal, session: CK_SESSION_HANDLE, last_encrypted_part: CK_BYTE_PTR, last_encrypted_part_len: CK_ULONG_PTR);
    proxy_method!(decrypt_init, C_DecryptInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(decrypt, C_Decrypt, session: CK_SESSION_HANDLE, encrypted_data: CK_BYTE_PTR, encrypted_data_len: CK_ULONG, data: CK_BYTE_PTR, data_len: CK_ULONG_PTR);
    proxy_method!(decrypt_update, C_DecryptUpdate, session: CK_SESSION_HANDLE, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG, part: CK_BYTE_PTR, part_len: CK_ULONG_PTR);
    proxy_method!(decrypt_final, C_DecryptFinal, session: CK_SESSION_HANDLE, last_part: CK_BYTE_PTR, last_part_len: CK_ULONG_PTR);
    proxy_method!(digest_init, C_DigestInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR);
    proxy_method!(digest, C_Digest, session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, data_len: CK_ULONG, digest: CK_BYTE_PTR, digest_len: CK_ULONG_PTR);
    proxy_method!(digest_update, C_DigestUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG);
    proxy_method!(digest_key, C_DigestKey, session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE);
    proxy_method!(digest_final, C_DigestFinal, session: CK_SESSION_HANDLE, digest: CK_BYTE_PTR, digest_len: CK_ULONG_PTR);
    proxy_method!(sign_init, C_SignInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(sign, C_Sign, session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, data_len: CK_ULONG, signature: CK_BYTE_PTR, signature_len: CK_ULONG_PTR);
    proxy_method!(sign_update, C_SignUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG);
    proxy_method!(sign_final, C_SignFinal, session: CK_SESSION_HANDLE, signature: CK_BYTE_PTR, signature_len: CK_ULONG_PTR);
    proxy_method!(sign_recover_init, C_SignRecoverInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(sign_recover, C_SignRecover, session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, data_len: CK_ULONG, signature: CK_BYTE_PTR, signature_len: CK_ULONG_PTR);
    proxy_method!(verify_init, C_VerifyInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(verify, C_Verify, session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, data_len: CK_ULONG, signature: CK_BYTE_PTR, signature_len: CK_ULONG);
    proxy_method!(verify_update, C_VerifyUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG);
    proxy_method!(verify_final, C_VerifyFinal, session: CK_SESSION_HANDLE, signature: CK_BYTE_PTR, signature_len: CK_ULONG);
    proxy_method!(verify_recover_init, C_VerifyRecoverInit, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE);
    proxy_method!(verify_recover, C_VerifyRecover, session: CK_SESSION_HANDLE, signature: CK_BYTE_PTR, signature_len: CK_ULONG, data: CK_BYTE_PTR, data_len: CK_ULONG_PTR);
    proxy_method!(digest_encrypt_update, C_DigestEncryptUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG_PTR);
    proxy_method!(decrypt_digest_update, C_DecryptDigestUpdate, session: CK_SESSION_HANDLE, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG, part: CK_BYTE_PTR, part_len: CK_ULONG_PTR);
    proxy_method!(sign_encrypt_update, C_SignEncryptUpdate, session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, part_len: CK_ULONG, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG_PTR);
    proxy_method!(decrypt_verify_update, C_DecryptVerifyUpdate, session: CK_SESSION_HANDLE, encrypted_part: CK_BYTE_PTR, encrypted_part_len: CK_ULONG, part: CK_BYTE_PTR, part_len: CK_ULONG_PTR);
    proxy_method!(generate_key, C_GenerateKey, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, template: CK_ATTRIBUTE_PTR, count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR);
    proxy_method!(generate_key_pair, C_GenerateKeyPair, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, public_key_template: CK_ATTRIBUTE_PTR, public_key_attribute_count: CK_ULONG, private_key_template: CK_ATTRIBUTE_PTR, private_key_attribute_count: CK_ULONG, public_key: CK_OBJECT_HANDLE_PTR, private_key: CK_OBJECT_HANDLE_PTR);
    proxy_method!(wrap_key, C_WrapKey, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, wrapping_key: CK_OBJECT_HANDLE, key: CK_OBJECT_HANDLE, wrapped_key: CK_BYTE_PTR, wrapped_key_len: CK_ULONG_PTR);
    proxy_method!(unwrap_key, C_UnwrapKey, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, unwrapping_key: CK_OBJECT_HANDLE, wrapped_key: CK_BYTE_PTR, wrapped_key_len: CK_ULONG, template: CK_ATTRIBUTE_PTR, attribute_count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR);
    proxy_method!(derive_key, C_DeriveKey, session: CK_SESSION_HANDLE, mechanism: CK_MECHANISM_PTR, base_key: CK_OBJECT_HANDLE, template: CK_ATTRIBUTE_PTR, attribute_count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR);
    proxy_method!(seed_random, C_SeedRandom, session: CK_SESSION_HANDLE, seed: CK_BYTE_PTR, seed_len: CK_ULONG);
    proxy_method!(generate_random, C_GenerateRandom, session: CK_SESSION_HANDLE, random_data: CK_BYTE_PTR, random_len: CK_ULONG);
    proxy_method!(get_function_status, C_GetFunctionStatus, session: CK_SESSION_HANDLE);
    proxy_method!(cancel_function, C_CancelFunction, session: CK_SESSION_HANDLE);
    proxy_method!(wait_for_slot_event, C_WaitForSlotEvent, flags: CK_FLAGS, slot: CK_SLOT_ID_PTR, reserved: CK_VOID_PTR);


    /// Get token info and map slot to label for auto-login
    pub fn get_token_info(&self, slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
        let rv = match self.funcs().C_GetTokenInfo {
            Some(f) => unsafe { f(slot_id, info) },
            None => return CKR_FUNCTION_NOT_SUPPORTED,
        };

        if rv != CKR_OK || info.is_null() {
            return rv;
        }

        // Extract label and check if we have a PIN for it
        let label = Self::extract_token_label(unsafe { &*info });
        debug!("Called get_token_info(): {}", label);
        if self.config.get_pin_for_label(&label).is_some() {
            debug!("Found PIN for slot {} (token '{}')", slot_id, label);
            self.slot_to_label.write().insert(slot_id, label);
            // Clear protected authentication path flag so the app will call Login
            unsafe {
                (*info).flags &= !CKF_PROTECTED_AUTHENTICATION_PATH;
            }
        }

        rv
    }

    /// Open session and auto-login if we have a PIN
    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        application: CK_VOID_PTR,
        notify: CK_NOTIFY,
        session: CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
        let rv = match self.funcs().C_OpenSession {
            Some(f) => unsafe { f(slot_id, flags, application, notify, session) },
            None => return CKR_FUNCTION_NOT_SUPPORTED,
        };

        if rv != CKR_OK {
            return rv;
        }

        // Auto-login if we have a PIN for this slot
        if let Some(label) = self.slot_to_label.read().get(&slot_id) {
            if let Some(pin) = self.config.get_pin_for_label(label) {
                debug!("Auto-login for slot {} (token '{}')", slot_id, label);
                let session_handle = unsafe { *session };
                let login_rv = self.login(
                    session_handle,
                    CKU_USER,
                    pin.as_ptr() as CK_UTF8CHAR_PTR,
                    pin.len() as CK_ULONG,
                );
                if login_rv != CKR_OK && login_rv != CKR_USER_ALREADY_LOGGED_IN {
                    warn!("Auto-login failed for token '{}': {}", label, login_rv);
                }
            }
        }

        rv
    }

    fn extract_token_label(info: &CK_TOKEN_INFO) -> String {
        let label_bytes = &info.label[..];
        let end = label_bytes
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        String::from_utf8_lossy(&label_bytes[..end]).to_string()
    }
}
