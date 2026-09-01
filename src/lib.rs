#![allow(non_snake_case)] // PKCS#11 uses camelCase parameter names

mod backend;
mod config;
mod pkcs11_types;

use backend::Backend;
use config::Config;
use log::{debug, error, info};
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use pkcs11_types::*;
use std::panic::{self, AssertUnwindSafe};

/// Global backend instance
static BACKEND: OnceCell<Backend> = OnceCell::new();
static INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

/// Initialize logging
fn init_logging(debug: bool) {
    use env_logger::Builder;
    use log::LevelFilter;
    use std::io::Write;

    let level = if debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let _ = Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "[pkcs11-autopin] {} - {}",
                record.level(),
                record.args()
            )
        })
        .filter(None, level)
        .try_init();
}

/// Get the backend, initializing if necessary
fn get_backend() -> Result<&'static Backend, CK_RV> {
    if !*INITIALIZED.lock() {
        return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    BACKEND.get().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)
}

/// Wrap a function call with panic handling
fn wrap_call<F>(name: &str, f: F) -> CK_RV
where
    F: FnOnce() -> CK_RV,
{
    debug!("Called {}()", name);

    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(rv) => rv,
        Err(e) => {
            error!("{}() panicked: {:?}", name, e);
            CKR_FUNCTION_FAILED
        }
    }
}

// === Macro for generating simple proxy functions ===

/// Generate a proxy function that forwards to backend
macro_rules! proxy_fn {
    // No arguments
    ($name:ident, $backend_method:ident) => {
        #[no_mangle]
        pub extern "C" fn $name() -> CK_RV {
            wrap_call(stringify!($name), || {
                match get_backend() {
                    Ok(b) => b.$backend_method(),
                    Err(rv) => rv,
                }
            })
        }
    };
    // With arguments
    ($name:ident, $backend_method:ident, $($arg:ident : $ty:ty),+) => {
        #[no_mangle]
        pub extern "C" fn $name($($arg: $ty),+) -> CK_RV {
            wrap_call(stringify!($name), || {
                match get_backend() {
                    Ok(b) => b.$backend_method($($arg),+),
                    Err(rv) => rv,
                }
            })
        }
    };
}

// === PKCS#11 Exported Functions ===

#[no_mangle]
pub extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    let result = BACKEND.get_or_try_init(|| {
        let config = Config::load().map_err(|e| {
            eprintln!("[pkcs11-autopin] Failed to load config: {}", e);
            CKR_FUNCTION_FAILED
        })?;

        init_logging(config.debug);
        info!("Initializing pkcs11-autopin proxy");
        info!("Backend: {}", config.backend_path);

        Backend::new(config).map_err(|e| {
            error!("Failed to load backend: {}", e);
            CKR_FUNCTION_FAILED
        })
    });

    match result {
        Ok(backend) => wrap_call("C_Initialize", || {
            let mut initialized = INITIALIZED.lock();
            if *initialized {
                return CKR_CRYPTOKI_ALREADY_INITIALIZED;
            }

            let rv = backend.initialize(pInitArgs);
            if rv == CKR_OK {
                *initialized = true;
            }
            rv
        }),
        Err(rv) => rv,
    }
}

// General purpose functions
#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    wrap_call("C_Finalize", || {
        let backend = match BACKEND.get() {
            Some(backend) => backend,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };

        let mut initialized = INITIALIZED.lock();
        if !*initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }

        let rv = backend.finalize(pReserved);
        if rv == CKR_OK {
            *initialized = false;
        }
        rv
    })
}

proxy_fn!(C_GetInfo, get_info, pInfo: CK_INFO_PTR);

// Slot and token management
proxy_fn!(C_GetSlotList, get_slot_list, tokenPresent: CK_BBOOL, pSlotList: CK_SLOT_ID_PTR, pulCount: CK_ULONG_PTR);
proxy_fn!(C_GetSlotInfo, get_slot_info, slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR);
proxy_fn!(C_GetTokenInfo, get_token_info, slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR);
proxy_fn!(C_GetMechanismList, get_mechanism_list, slotID: CK_SLOT_ID, pMechanismList: CK_MECHANISM_TYPE_PTR, pulCount: CK_ULONG_PTR);
proxy_fn!(C_GetMechanismInfo, get_mechanism_info, slotID: CK_SLOT_ID, type_: CK_MECHANISM_TYPE, pInfo: CK_MECHANISM_INFO_PTR);
proxy_fn!(C_InitToken, init_token, slotID: CK_SLOT_ID, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG, pLabel: CK_UTF8CHAR_PTR);
proxy_fn!(C_InitPIN, init_pin, hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG);
proxy_fn!(C_SetPIN, set_pin, hSession: CK_SESSION_HANDLE, pOldPin: CK_UTF8CHAR_PTR, ulOldLen: CK_ULONG, pNewPin: CK_UTF8CHAR_PTR, ulNewLen: CK_ULONG);

// Session management
proxy_fn!(C_OpenSession, open_session, slotID: CK_SLOT_ID, flags: CK_FLAGS, pApplication: CK_VOID_PTR, Notify: CK_NOTIFY, phSession: CK_SESSION_HANDLE_PTR);
proxy_fn!(C_CloseSession, close_session, hSession: CK_SESSION_HANDLE);
proxy_fn!(C_CloseAllSessions, close_all_sessions, slotID: CK_SLOT_ID);
proxy_fn!(C_GetSessionInfo, get_session_info, hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR);
proxy_fn!(C_GetOperationState, get_operation_state, hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, pulOperationStateLen: CK_ULONG_PTR);
proxy_fn!(C_SetOperationState, set_operation_state, hSession: CK_SESSION_HANDLE, pOperationState: CK_BYTE_PTR, ulOperationStateLen: CK_ULONG, hEncryptionKey: CK_OBJECT_HANDLE, hAuthenticationKey: CK_OBJECT_HANDLE);
proxy_fn!(C_Login, login, hSession: CK_SESSION_HANDLE, userType: CK_USER_TYPE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG);
proxy_fn!(C_Logout, logout, hSession: CK_SESSION_HANDLE);

// Object management
proxy_fn!(C_CreateObject, create_object, hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phObject: CK_OBJECT_HANDLE_PTR);
proxy_fn!(C_CopyObject, copy_object, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phNewObject: CK_OBJECT_HANDLE_PTR);
proxy_fn!(C_DestroyObject, destroy_object, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE);
proxy_fn!(C_GetObjectSize, get_object_size, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pulSize: CK_ULONG_PTR);
proxy_fn!(C_GetAttributeValue, get_attribute_value, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG);
proxy_fn!(C_SetAttributeValue, set_attribute_value, hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG);
proxy_fn!(C_FindObjectsInit, find_objects_init, hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG);
proxy_fn!(C_FindObjects, find_objects, hSession: CK_SESSION_HANDLE, phObject: CK_OBJECT_HANDLE_PTR, ulMaxObjectCount: CK_ULONG, pulObjectCount: CK_ULONG_PTR);
proxy_fn!(C_FindObjectsFinal, find_objects_final, hSession: CK_SESSION_HANDLE);

// Encryption
proxy_fn!(C_EncryptInit, encrypt_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_Encrypt, encrypt, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pEncryptedData: CK_BYTE_PTR, pulEncryptedDataLen: CK_ULONG_PTR);
proxy_fn!(C_EncryptUpdate, encrypt_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
proxy_fn!(C_EncryptFinal, encrypt_final, hSession: CK_SESSION_HANDLE, pLastEncryptedPart: CK_BYTE_PTR, pulLastEncryptedPartLen: CK_ULONG_PTR);

// Decryption
proxy_fn!(C_DecryptInit, decrypt_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_Decrypt, decrypt, hSession: CK_SESSION_HANDLE, pEncryptedData: CK_BYTE_PTR, ulEncryptedDataLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR);
proxy_fn!(C_DecryptUpdate, decrypt_update, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);
proxy_fn!(C_DecryptFinal, decrypt_final, hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR);

// Digest
proxy_fn!(C_DigestInit, digest_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR);
proxy_fn!(C_Digest, digest, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR);
proxy_fn!(C_DigestUpdate, digest_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG);
proxy_fn!(C_DigestKey, digest_key, hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_DigestFinal, digest_final, hSession: CK_SESSION_HANDLE, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR);

// Signing
proxy_fn!(C_SignInit, sign_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_Sign, sign, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR);
proxy_fn!(C_SignUpdate, sign_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG);
proxy_fn!(C_SignFinal, sign_final, hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR);
proxy_fn!(C_SignRecoverInit, sign_recover_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_SignRecover, sign_recover, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR);

// Verification
proxy_fn!(C_VerifyInit, verify_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_Verify, verify, hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG);
proxy_fn!(C_VerifyUpdate, verify_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG);
proxy_fn!(C_VerifyFinal, verify_final, hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG);
proxy_fn!(C_VerifyRecoverInit, verify_recover_init, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE);
proxy_fn!(C_VerifyRecover, verify_recover, hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR);

// Dual-function crypto
proxy_fn!(C_DigestEncryptUpdate, digest_encrypt_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
proxy_fn!(C_DecryptDigestUpdate, decrypt_digest_update, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);
proxy_fn!(C_SignEncryptUpdate, sign_encrypt_update, hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR);
proxy_fn!(C_DecryptVerifyUpdate, decrypt_verify_update, hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR);

// Key management
proxy_fn!(C_GenerateKey, generate_key, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);
proxy_fn!(C_GenerateKeyPair, generate_key_pair, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pPublicKeyTemplate: CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount: CK_ULONG, pPrivateKeyTemplate: CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount: CK_ULONG, phPublicKey: CK_OBJECT_HANDLE_PTR, phPrivateKey: CK_OBJECT_HANDLE_PTR);
proxy_fn!(C_WrapKey, wrap_key, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hWrappingKey: CK_OBJECT_HANDLE, hKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, pulWrappedKeyLen: CK_ULONG_PTR);
proxy_fn!(C_UnwrapKey, unwrap_key, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hUnwrappingKey: CK_OBJECT_HANDLE, pWrappedKey: CK_BYTE_PTR, ulWrappedKeyLen: CK_ULONG, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);
proxy_fn!(C_DeriveKey, derive_key, hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hBaseKey: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulAttributeCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR);

// Random
proxy_fn!(C_SeedRandom, seed_random, hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG);
proxy_fn!(C_GenerateRandom, generate_random, hSession: CK_SESSION_HANDLE, pRandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG);

// Parallel function management (legacy)
proxy_fn!(C_GetFunctionStatus, get_function_status, hSession: CK_SESSION_HANDLE);
proxy_fn!(C_CancelFunction, cancel_function, hSession: CK_SESSION_HANDLE);

// Slot event
proxy_fn!(C_WaitForSlotEvent, wait_for_slot_event, flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pReserved: CK_VOID_PTR);

/// Static function list for C_GetFunctionList
static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

/// Returns the proxy's PKCS#11 function table.
///
/// # Safety
///
/// If non-null, `ppFunctionList` must be valid and aligned for writing one
/// [`CK_FUNCTION_LIST_PTR`].
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = std::ptr::addr_of_mut!(FUNCTION_LIST);
    CKR_OK
}
