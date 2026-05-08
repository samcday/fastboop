pub(crate) fn js_value_to_string(value: &wasm_bindgen::JsValue) -> String {
    js_sys::JSON::stringify(value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}
