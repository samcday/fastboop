#[cfg(target_arch = "wasm32")]
pub(crate) fn js_value_to_string(value: &wasm_bindgen::JsValue) -> String {
    js_sys::JSON::stringify(value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn current_module_script_url(preferred_name_fragment: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;
    use web_sys::HtmlScriptElement;

    let window = web_sys::window().ok_or_else(|| "window is unavailable".to_string())?;
    let document = window
        .document()
        .ok_or_else(|| "document is unavailable".to_string())?;
    let scripts = document.scripts();

    let mut preferred_candidate = None;
    let mut module_candidates = Vec::new();
    let mut js_candidates = Vec::new();
    for index in 0..scripts.length() {
        let Some(script) = scripts.item(index) else {
            continue;
        };
        let Ok(script) = script.dyn_into::<HtmlScriptElement>() else {
            continue;
        };
        let src = script.src();
        if !script_url_path(&src).ends_with(".js") {
            continue;
        }
        if !preferred_name_fragment.is_empty() && src.contains(preferred_name_fragment) {
            preferred_candidate = Some(src.clone());
        }
        if script.type_().eq_ignore_ascii_case("module") {
            module_candidates.push(src.clone());
        }
        js_candidates.push(src);
    }

    if let Some(candidate) = preferred_candidate {
        return Ok(candidate);
    }
    if module_candidates.len() == 1 {
        return Ok(module_candidates.remove(0));
    }
    if js_candidates.len() == 1 {
        return Ok(js_candidates.remove(0));
    }

    Err(format!(
        "failed to determine fastboop web module script URL (preferred fragment '{preferred_name_fragment}', module script candidates {}, JS script candidates {})",
        module_candidates.len(),
        js_candidates.len()
    ))
}

#[cfg(target_arch = "wasm32")]
fn script_url_path(src: &str) -> &str {
    let query = src.find('?').unwrap_or(src.len());
    let fragment = src.find('#').unwrap_or(src.len());
    &src[..query.min(fragment)]
}
