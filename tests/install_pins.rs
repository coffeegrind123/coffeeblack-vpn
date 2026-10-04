//! The host installer and the Docker image must run the same amneziawg-tools.
//!
//! `scripts/install.sh` builds the tools on bare-metal hosts and the
//! `Dockerfile` builds them into the image, each from a pinned tag plus an
//! asserted commit SHA. A bump to one without the other leaves the two
//! deployment shapes parsing configs differently, so this fails the build
//! when the pins disagree.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Value of `<prefix><name>=<value>` in a shell or Dockerfile, quotes stripped.
fn pin(text: &str, prefix: &str, name: &str) -> String {
    let key = format!("{prefix}{name}=");
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&key))
        .unwrap_or_else(|| panic!("no `{key}` line"));
    line[key.len()..].trim_matches('"').to_string()
}

#[test]
fn installer_tools_pin_matches_the_dockerfile() {
    let dockerfile = read("Dockerfile");
    let installer = read("scripts/install.sh");

    for name in ["AWG_TOOLS_TAG", "AWG_TOOLS_SHA"] {
        assert_eq!(
            pin(&installer, "readonly ", name),
            pin(&dockerfile, "ARG ", name),
            "{name} differs between scripts/install.sh and Dockerfile; bump both together"
        );
    }
}

#[test]
fn installer_pins_are_well_formed() {
    let installer = read("scripts/install.sh");
    for (tag, sha) in [("AWG_KMOD_TAG", "AWG_KMOD_SHA"), ("AWG_TOOLS_TAG", "AWG_TOOLS_SHA")] {
        let tag = pin(&installer, "readonly ", tag);
        let sha = pin(&installer, "readonly ", sha);
        assert!(tag.starts_with('v') && tag[1..].split('.').all(|p| p.parse::<u64>().is_ok()), "{tag}");
        assert!(sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "{sha}");
    }
}
