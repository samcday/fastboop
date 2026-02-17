extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, Default)]
pub struct Personalization {
    pub locale: Option<String>,
    pub locale_messages: Option<String>,
    pub keymap: Option<String>,
    pub timezone: Option<String>,
}

impl Personalization {
    pub fn stage0_entries(&self) -> Vec<(String, String)> {
        let mut entries = Vec::new();
        push_entry(&mut entries, "firstboot.locale", self.locale.as_deref());
        push_entry(
            &mut entries,
            "firstboot.locale-messages",
            self.locale_messages.as_deref(),
        );
        push_entry(&mut entries, "firstboot.keymap", self.keymap.as_deref());
        push_entry(&mut entries, "firstboot.timezone", self.timezone.as_deref());
        entries
    }
}

fn push_entry(out: &mut Vec<(String, String)>, name: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim) else {
        return;
    };
    if value.is_empty() {
        return;
    }
    out.push((name.to_string(), value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn stage0_entries_include_non_empty_values_only() {
        let personalization = Personalization {
            locale: Some("en_US.UTF-8".to_string()),
            locale_messages: Some("".to_string()),
            keymap: Some("us".to_string()),
            timezone: None,
        };

        let entries = personalization.stage0_entries();
        assert_eq!(
            entries,
            vec![
                ("firstboot.locale".to_string(), "en_US.UTF-8".to_string()),
                ("firstboot.keymap".to_string(), "us".to_string()),
            ]
        );
    }
}
