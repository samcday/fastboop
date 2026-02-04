use fastboop_core::builtin::builtin_profiles;

#[test]
fn builtin_profiles_roundtrip() {
    let profiles = builtin_profiles().expect("builtin profiles decode");
    assert!(!profiles.is_empty(), "expected builtin profiles to load");
}
