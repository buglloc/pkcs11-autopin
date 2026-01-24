//! PKCS#11 type definitions and constants
#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

// Basic types
pub type CK_BYTE = u8;
pub type CK_CHAR = u8;
pub type CK_UTF8CHAR = u8;
pub type CK_BBOOL = u8;
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_LONG = std::ffi::c_long;
pub type CK_FLAGS = CK_ULONG;
pub type CK_RV = CK_ULONG;

pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_CHAR_PTR = *mut CK_CHAR;
pub type CK_UTF8CHAR_PTR = *mut CK_UTF8CHAR;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_VOID_PTR = *mut c_void;

// Handle types
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;

pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;

// Constants
pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_TRUE: CK_BBOOL = 1;

pub const CKU_SO: CK_USER_TYPE = 0;
pub const CKU_USER: CK_USER_TYPE = 1;
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

// Return values
pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY: CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_NO_EVENT: CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS: CK_RV = 0x00000009;
pub const CKR_CANT_LOCK: CK_RV = 0x0000000A;
pub const CKR_ATTRIBUTE_READ_ONLY: CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE: CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CK_RV = 0x00000013;
pub const CKR_ACTION_PROHIBITED: CK_RV = 0x0000001B;
pub const CKR_DATA_INVALID: CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE: CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY: CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED: CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID: CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED: CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL: CK_RV = 0x00000051;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE: CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000063;
pub const CKR_KEY_NOT_NEEDED: CK_RV = 0x00000064;
pub const CKR_KEY_CHANGED: CK_RV = 0x00000065;
pub const CKR_KEY_NEEDED: CK_RV = 0x00000066;
pub const CKR_KEY_INDIGESTIBLE: CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE: CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE: CK_RV = 0x0000006A;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE: CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID: CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE: CK_RV = 0x000000A2;
pub const CKR_PIN_EXPIRED: CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED: CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT: CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS: CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS: CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CK_RV = 0x000000B8;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE: CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT: CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED: CK_RV = 0x000000E2;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x000000F0;
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE: CK_RV = 0x000000F1;
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x000000F2;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES: CK_RV = 0x00000105;
pub const CKR_WRAPPED_KEY_INVALID: CK_RV = 0x00000110;
pub const CKR_WRAPPED_KEY_LEN_RANGE: CK_RV = 0x00000112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x00000113;
pub const CKR_WRAPPING_KEY_SIZE_RANGE: CK_RV = 0x00000114;
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000115;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CK_RV = 0x00000120;
pub const CKR_RANDOM_NO_RNG: CK_RV = 0x00000121;
pub const CKR_DOMAIN_PARAMS_INVALID: CK_RV = 0x00000130;
pub const CKR_CURVE_NOT_SUPPORTED: CK_RV = 0x00000140;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_SAVED_STATE_INVALID: CK_RV = 0x00000160;
pub const CKR_INFORMATION_SENSITIVE: CK_RV = 0x00000170;
pub const CKR_STATE_UNSAVEABLE: CK_RV = 0x00000180;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD: CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED: CK_RV = 0x000001A1;

// Token flags
pub const CKF_RNG: CK_FLAGS = 0x00000001;
pub const CKF_WRITE_PROTECTED: CK_FLAGS = 0x00000002;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;
pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x00000020;
pub const CKF_CLOCK_ON_TOKEN: CK_FLAGS = 0x00000040;
pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x00000100;
pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x00000200;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_SECONDARY_AUTHENTICATION: CK_FLAGS = 0x00000800;
pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x00010000;
pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x00020000;
pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x00040000;
pub const CKF_USER_PIN_TO_BE_CHANGED: CK_FLAGS = 0x00080000;
pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x00100000;
pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x00200000;
pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x00400000;
pub const CKF_SO_PIN_TO_BE_CHANGED: CK_FLAGS = 0x00800000;

// Structures
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_INFO {
    pub cryptokiVersion: CK_VERSION,
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub libraryDescription: [CK_UTF8CHAR; 32],
    pub libraryVersion: CK_VERSION,
}

pub type CK_INFO_PTR = *mut CK_INFO;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [CK_UTF8CHAR; 64],
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}

pub type CK_SLOT_INFO_PTR = *mut CK_SLOT_INFO;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serialNumber: [CK_CHAR; 16],
    pub flags: CK_FLAGS,
    pub ulMaxSessionCount: CK_ULONG,
    pub ulSessionCount: CK_ULONG,
    pub ulMaxRwSessionCount: CK_ULONG,
    pub ulRwSessionCount: CK_ULONG,
    pub ulMaxPinLen: CK_ULONG,
    pub ulMinPinLen: CK_ULONG,
    pub ulTotalPublicMemory: CK_ULONG,
    pub ulFreePublicMemory: CK_ULONG,
    pub ulTotalPrivateMemory: CK_ULONG,
    pub ulFreePrivateMemory: CK_ULONG,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [CK_CHAR; 16],
}

pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

pub type CK_SESSION_INFO_PTR = *mut CK_SESSION_INFO;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: CK_VOID_PTR,
    pub ulParameterLen: CK_ULONG,
}

pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

pub type CK_MECHANISM_INFO_PTR = *mut CK_MECHANISM_INFO;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_ATTRIBUTE {
    pub attrType: CK_ATTRIBUTE_TYPE,
    pub pValue: CK_VOID_PTR,
    pub ulValueLen: CK_ULONG,
}

pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;

// Callback type
pub type CK_NOTIFY = Option<
    unsafe extern "C" fn(
        hSession: CK_SESSION_HANDLE,
        event: CK_ULONG,
        pApplication: CK_VOID_PTR,
    ) -> CK_RV,
>;

// Function types for the backend
pub type CK_C_Initialize = unsafe extern "C" fn(pInitArgs: CK_VOID_PTR) -> CK_RV;
pub type CK_C_Finalize = unsafe extern "C" fn(pReserved: CK_VOID_PTR) -> CK_RV;
pub type CK_C_GetInfo = unsafe extern "C" fn(pInfo: CK_INFO_PTR) -> CK_RV;
pub type CK_C_GetSlotList = unsafe extern "C" fn(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_GetSlotInfo =
    unsafe extern "C" fn(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV;
pub type CK_C_GetTokenInfo =
    unsafe extern "C" fn(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV;
pub type CK_C_GetMechanismList = unsafe extern "C" fn(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_GetMechanismInfo = unsafe extern "C" fn(
    slotID: CK_SLOT_ID,
    mechType: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV;
pub type CK_C_InitToken = unsafe extern "C" fn(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV;
pub type CK_C_InitPIN =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG) -> CK_RV;
pub type CK_C_SetPIN = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pOldPin: CK_UTF8CHAR_PTR,
    ulOldLen: CK_ULONG,
    pNewPin: CK_UTF8CHAR_PTR,
    ulNewLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_OpenSession = unsafe extern "C" fn(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_CloseSession = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CloseAllSessions = unsafe extern "C" fn(slotID: CK_SLOT_ID) -> CK_RV;
pub type CK_C_GetSessionInfo =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV;
pub type CK_C_GetOperationState = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SetOperationState = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Login = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_Logout = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CreateObject = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_CopyObject = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_DestroyObject =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_GetObjectSize = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_GetAttributeValue = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV;
pub type CK_C_SetAttributeValue = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV;
pub type CK_C_FindObjectsInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV;
pub type CK_C_FindObjects = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_FindObjectsFinal = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_EncryptInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Encrypt = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_EncryptUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_EncryptFinal = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DecryptInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Decrypt = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DecryptUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DecryptFinal = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DigestInit =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV;
pub type CK_C_Digest = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DigestUpdate =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;
pub type CK_C_DigestKey =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_DigestFinal = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SignInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Sign = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SignUpdate =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;
pub type CK_C_SignFinal = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SignRecoverInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_SignRecover = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_VerifyInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Verify = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_VerifyUpdate =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;
pub type CK_C_VerifyFinal = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_VerifyRecoverInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_VerifyRecover = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DigestEncryptUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DecryptDigestUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SignEncryptUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_DecryptVerifyUpdate = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_GenerateKey = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_GenerateKeyPair = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_WrapKey = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_UnwrapKey = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_DeriveKey = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_SeedRandom =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG) -> CK_RV;
pub type CK_C_GenerateRandom = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pRandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_GetFunctionStatus = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CancelFunction = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_WaitForSlotEvent =
    unsafe extern "C" fn(flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pReserved: CK_VOID_PTR) -> CK_RV;

// Function list structure
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: Option<CK_C_Initialize>,
    pub C_Finalize: Option<CK_C_Finalize>,
    pub C_GetInfo: Option<CK_C_GetInfo>,
    pub C_GetFunctionList:
        Option<unsafe extern "C" fn(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList: Option<CK_C_GetSlotList>,
    pub C_GetSlotInfo: Option<CK_C_GetSlotInfo>,
    pub C_GetTokenInfo: Option<CK_C_GetTokenInfo>,
    pub C_GetMechanismList: Option<CK_C_GetMechanismList>,
    pub C_GetMechanismInfo: Option<CK_C_GetMechanismInfo>,
    pub C_InitToken: Option<CK_C_InitToken>,
    pub C_InitPIN: Option<CK_C_InitPIN>,
    pub C_SetPIN: Option<CK_C_SetPIN>,
    pub C_OpenSession: Option<CK_C_OpenSession>,
    pub C_CloseSession: Option<CK_C_CloseSession>,
    pub C_CloseAllSessions: Option<CK_C_CloseAllSessions>,
    pub C_GetSessionInfo: Option<CK_C_GetSessionInfo>,
    pub C_GetOperationState: Option<CK_C_GetOperationState>,
    pub C_SetOperationState: Option<CK_C_SetOperationState>,
    pub C_Login: Option<CK_C_Login>,
    pub C_Logout: Option<CK_C_Logout>,
    pub C_CreateObject: Option<CK_C_CreateObject>,
    pub C_CopyObject: Option<CK_C_CopyObject>,
    pub C_DestroyObject: Option<CK_C_DestroyObject>,
    pub C_GetObjectSize: Option<CK_C_GetObjectSize>,
    pub C_GetAttributeValue: Option<CK_C_GetAttributeValue>,
    pub C_SetAttributeValue: Option<CK_C_SetAttributeValue>,
    pub C_FindObjectsInit: Option<CK_C_FindObjectsInit>,
    pub C_FindObjects: Option<CK_C_FindObjects>,
    pub C_FindObjectsFinal: Option<CK_C_FindObjectsFinal>,
    pub C_EncryptInit: Option<CK_C_EncryptInit>,
    pub C_Encrypt: Option<CK_C_Encrypt>,
    pub C_EncryptUpdate: Option<CK_C_EncryptUpdate>,
    pub C_EncryptFinal: Option<CK_C_EncryptFinal>,
    pub C_DecryptInit: Option<CK_C_DecryptInit>,
    pub C_Decrypt: Option<CK_C_Decrypt>,
    pub C_DecryptUpdate: Option<CK_C_DecryptUpdate>,
    pub C_DecryptFinal: Option<CK_C_DecryptFinal>,
    pub C_DigestInit: Option<CK_C_DigestInit>,
    pub C_Digest: Option<CK_C_Digest>,
    pub C_DigestUpdate: Option<CK_C_DigestUpdate>,
    pub C_DigestKey: Option<CK_C_DigestKey>,
    pub C_DigestFinal: Option<CK_C_DigestFinal>,
    pub C_SignInit: Option<CK_C_SignInit>,
    pub C_Sign: Option<CK_C_Sign>,
    pub C_SignUpdate: Option<CK_C_SignUpdate>,
    pub C_SignFinal: Option<CK_C_SignFinal>,
    pub C_SignRecoverInit: Option<CK_C_SignRecoverInit>,
    pub C_SignRecover: Option<CK_C_SignRecover>,
    pub C_VerifyInit: Option<CK_C_VerifyInit>,
    pub C_Verify: Option<CK_C_Verify>,
    pub C_VerifyUpdate: Option<CK_C_VerifyUpdate>,
    pub C_VerifyFinal: Option<CK_C_VerifyFinal>,
    pub C_VerifyRecoverInit: Option<CK_C_VerifyRecoverInit>,
    pub C_VerifyRecover: Option<CK_C_VerifyRecover>,
    pub C_DigestEncryptUpdate: Option<CK_C_DigestEncryptUpdate>,
    pub C_DecryptDigestUpdate: Option<CK_C_DecryptDigestUpdate>,
    pub C_SignEncryptUpdate: Option<CK_C_SignEncryptUpdate>,
    pub C_DecryptVerifyUpdate: Option<CK_C_DecryptVerifyUpdate>,
    pub C_GenerateKey: Option<CK_C_GenerateKey>,
    pub C_GenerateKeyPair: Option<CK_C_GenerateKeyPair>,
    pub C_WrapKey: Option<CK_C_WrapKey>,
    pub C_UnwrapKey: Option<CK_C_UnwrapKey>,
    pub C_DeriveKey: Option<CK_C_DeriveKey>,
    pub C_SeedRandom: Option<CK_C_SeedRandom>,
    pub C_GenerateRandom: Option<CK_C_GenerateRandom>,
    pub C_GetFunctionStatus: Option<CK_C_GetFunctionStatus>,
    pub C_CancelFunction: Option<CK_C_CancelFunction>,
    pub C_WaitForSlotEvent: Option<CK_C_WaitForSlotEvent>,
}

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

// Type for C_GetFunctionList
pub type CK_C_GetFunctionList =
    unsafe extern "C" fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

