use alloc::vec::Vec;

use crate::DeviceProfile;
use fastboop_schema::bin::DeviceProfileBin;

pub fn builtin_profiles() -> Result<Vec<DeviceProfile>, postcard::Error> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/builtin_devpros.bin"));
    let profiles: Vec<DeviceProfileBin> = postcard::from_bytes(bytes)?;
    Ok(profiles.into_iter().map(DeviceProfile::from).collect())
}
