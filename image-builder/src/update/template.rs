//! Strings holding `{version}`, as recipes write their URLs: substituted for a version, or
//! matched against text (a directory listing, tag names) to find the versions it names.

use std::collections::BTreeSet;

/// The placeholder of a recipe's version.
pub const VERSION: &str = "{version}";

/// `template` with `version` in place of `{version}`.
#[must_use]
pub fn substitute(template: &str, version: &str) -> String {
    template.replace(VERSION, version)
}

/// The versions `template` takes in `text`: each place where `text` reads as `template` with
/// a version (characters of `0-9A-Za-z._-`, starting and ending with an alphanumeric one) in
/// place of every `{version}`, the same each time. The text around the version is not checked
/// beyond the template's own.
#[must_use]
pub fn versions_in(template: &str, text: &str) -> BTreeSet<String> {
    let parts: Vec<&str> = template.split(VERSION).collect();
    let mut found = BTreeSet::new();
    let [first, rest @ ..] = parts.as_slice() else {
        return found;
    };
    if rest.is_empty() {
        return found;
    }
    let mut start = 0;
    while let Some(offset) = text[start..].find(first) {
        let at = start + offset + first.len();
        // Without text before it, a version starts where another word does not.
        let bounded = !first.is_empty() || !text[..at].ends_with(is_version_char);
        if bounded && let Some(version) = version_at(&text[at..], rest) {
            found.insert(version);
        }
        // The next match starts after this one's first character.
        let step = text[start + offset..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        start += offset + first.len().max(step);
        if start >= text.len() {
            break;
        }
    }
    found
}

/// Whether `c` may be in a version.
fn is_version_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// The version at the start of `text`, followed by `rest`'s parts, each after the same version.
fn version_at(text: &str, rest: &[&str]) -> Option<String> {
    let run = text.find(|c| !is_version_char(c)).unwrap_or(text.len());
    // The longest version followed by the template's next part.
    (1..=run).rev().find_map(|end| {
        let version = &text[..end];
        let bounded = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
        if !bounded(version.chars().next()) || !bounded(version.chars().last()) {
            return None;
        }
        let mut tail = &text[end..];
        for (i, part) in rest.iter().enumerate() {
            tail = tail.strip_prefix(part)?;
            if i + 1 < rest.len() {
                tail = tail.strip_prefix(version)?;
            }
        }
        Some(version.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions(template: &str, text: &str) -> Vec<String> {
        versions_in(template, text).into_iter().collect()
    }

    #[test]
    fn in_a_listing() {
        let listing = r#"<a href="glibc-2.43.tar.xz">glibc-2.43.tar.xz</a>
            <a href="glibc-2.44.tar.xz.sig">x</a> <a href="glibc-2.44.tar.xz">y</a>
            <a href="glibc-2.44.tar.gz">z</a> glibc-2.45.90.tar.xz"#;
        assert_eq!(
            versions("glibc-{version}.tar.xz", listing),
            ["2.43", "2.44", "2.45.90"]
        );
    }

    #[test]
    fn a_version_alone() {
        let listing = "<a href=\"2.0/\">2.0/</a> <a href=\"3.14.9/\">3.14.9/</a> é";
        assert_eq!(versions("{version}/", listing), ["2.0", "3.14.9"]);
    }

    #[test]
    fn the_same_version_each_time() {
        let text = "libslirp-v4.9.1/libslirp-v4.9.1.tar.gz libslirp-v4.9.2/libslirp-v4.9.1.tar.gz";
        assert_eq!(
            versions("libslirp-v{version}/libslirp-v{version}.tar.gz", text),
            ["4.9.1"]
        );
    }

    #[test]
    fn tags() {
        let tags = "refs/tags/v1.2.0\nrefs/tags/v1.3.0-rc1\nrefs/tags/v1.3.0\nrefs/tags/other";
        assert_eq!(
            versions("refs/tags/v{version}\n", &format!("{tags}\n")),
            ["1.2.0", "1.3.0", "1.3.0-rc1"]
        );
        assert_eq!(substitute("v{version}", "1.3.0"), "v1.3.0");
    }
}
