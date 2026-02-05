extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, Default)]
pub struct Personalization {
    pub locale: Option<String>,
    pub locale_messages: Option<String>,
    pub keymap: Option<String>,
    pub timezone: Option<String>,
}

impl Personalization {
    pub fn cmdline_append(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        push_credential(&mut parts, "firstboot.locale", self.locale.as_deref());
        push_credential(
            &mut parts,
            "firstboot.locale-messages",
            self.locale_messages.as_deref(),
        );
        push_credential(&mut parts, "firstboot.keymap", self.keymap.as_deref());
        push_credential(&mut parts, "firstboot.timezone", self.timezone.as_deref());
        parts.join(" ")
    }
}

fn push_credential(out: &mut Vec<String>, name: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim) else {
        return;
    };
    if value.is_empty() {
        return;
    }
    out.push(format!("systemd.set_credential={name}:{value}"));
}
