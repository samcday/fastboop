use std::fmt;

use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsbSnapshot {
    pub supported: bool,
    pub devices: Vec<UsbDevice>,
    pub last_permission_result: Option<String>,
}

impl UsbSnapshot {
    pub fn unsupported() -> Self {
        Self {
            supported: false,
            devices: Vec::new(),
            last_permission_result: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsbDevice {
    pub name: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub interface_count: u8,
    pub has_permission: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsbError {
    Unsupported,
    #[cfg(target_os = "android")]
    Android(String),
    #[cfg(target_os = "android")]
    Json(String),
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "Android USB host APIs are unavailable on this target"),
            #[cfg(target_os = "android")]
            Self::Android(err) => write!(f, "Android USB call failed: {err}"),
            #[cfg(target_os = "android")]
            Self::Json(err) => write!(f, "Android USB snapshot was invalid: {err}"),
        }
    }
}

impl std::error::Error for UsbError {}

pub fn snapshot() -> Result<UsbSnapshot, UsbError> {
    imp::snapshot()
}

pub fn request_permission(device_name: &str) -> Result<bool, UsbError> {
    imp::request_permission(device_name)
}

pub fn open_device_fd(device_name: &str) -> Result<i32, UsbError> {
    imp::open_device_fd(device_name)
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsbSnapshotPayload {
    #[serde(default)]
    devices: Vec<UsbDevice>,
    #[serde(default)]
    last_permission_result: Option<String>,
}

#[cfg(target_os = "android")]
mod imp {
    use jni::{
        objects::{JObject, JString, JValue},
        sys::jobject,
        JNIEnv, JavaVM,
    };

    use super::{UsbError, UsbSnapshot, UsbSnapshotPayload};

    pub fn snapshot() -> Result<UsbSnapshot, UsbError> {
        let raw = call_string_method("fastboopUsbSnapshot", "()Ljava/lang/String;")?;
        let payload: UsbSnapshotPayload =
            serde_json::from_str(&raw).map_err(|err| UsbError::Json(err.to_string()))?;
        Ok(UsbSnapshot {
            supported: true,
            devices: payload.devices,
            last_permission_result: payload.last_permission_result,
        })
    }

    pub fn request_permission(device_name: &str) -> Result<bool, UsbError> {
        call_string_bool_method(
            "fastboopRequestUsbPermission",
            "(Ljava/lang/String;)Z",
            device_name,
        )
    }

    pub fn open_device_fd(device_name: &str) -> Result<i32, UsbError> {
        call_string_int_method(
            "fastboopOpenUsbDevice",
            "(Ljava/lang/String;)I",
            device_name,
        )
    }

    fn call_string_method(method: &str, signature: &str) -> Result<String, UsbError> {
        with_env(|env, activity| {
            let value = env.call_method(&activity, method, signature, &[])?;
            let string = JString::from(value.l()?);
            let string = env.get_string(&string)?;
            Ok(string.into())
        })
    }

    fn call_string_bool_method(method: &str, signature: &str, arg: &str) -> Result<bool, UsbError> {
        with_env(|env, activity| {
            let arg = env.new_string(arg)?;
            let arg = JObject::from(arg);
            env.call_method(&activity, method, signature, &[JValue::Object(&arg)])?
                .z()
        })
    }

    fn call_string_int_method(method: &str, signature: &str, arg: &str) -> Result<i32, UsbError> {
        with_env(|env, activity| {
            let arg = env.new_string(arg)?;
            let arg = JObject::from(arg);
            env.call_method(&activity, method, signature, &[JValue::Object(&arg)])?
                .i()
        })
    }

    fn with_env<T>(
        f: impl for<'local> FnOnce(&mut JNIEnv<'local>, JObject<'local>) -> jni::errors::Result<T>,
    ) -> Result<T, UsbError> {
        let context = ndk_context::android_context();
        let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }
            .map_err(|err| UsbError::Android(err.to_string()))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|err| UsbError::Android(err.to_string()))?;
        let activity = unsafe { JObject::from_raw(context.context() as jobject) };
        let activity = env
            .new_local_ref(activity)
            .map_err(|err| UsbError::Android(err.to_string()))?;

        f(&mut env, activity).map_err(|err| UsbError::Android(err.to_string()))
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use super::{UsbError, UsbSnapshot};

    pub fn snapshot() -> Result<UsbSnapshot, UsbError> {
        Ok(UsbSnapshot::unsupported())
    }

    pub fn request_permission(_device_name: &str) -> Result<bool, UsbError> {
        Err(UsbError::Unsupported)
    }

    pub fn open_device_fd(_device_name: &str) -> Result<i32, UsbError> {
        Err(UsbError::Unsupported)
    }
}
