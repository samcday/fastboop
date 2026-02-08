pub fn oneplus_fajita_dtbo_overlays() -> Vec<Vec<u8>> {
    vec![
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/sdm845-oneplus-fajita-simplefb.dtbo"
        ))
        .to_vec(),
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/sdm845-oneplus-fajita-pmi8998-haptics.dtbo"
        ))
        .to_vec(),
    ]
}
