//! The repository must build on its own: no dependency may point outside it, and the OpenShell crates it uses must all
//! come from one pinned commit of NVIDIA's public repository. This guards the property a reviewer tests first (clone, build).

fn manifest() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).expect("Cargo.toml")
}

#[test]
fn no_dependency_points_outside_the_repository() {
    for (number, line) in manifest().lines().enumerate() {
        let code = line.split('#').next().unwrap_or("");
        assert!(
            !(code.contains("path") && code.contains("../")),
            "Cargo.toml line {}: a path dependency outside this repository would stop it building on its own: {line}",
            number + 1
        );
    }
}

#[test]
fn every_openshell_crate_is_pinned_to_the_same_commit() {
    let manifest = manifest();
    let mut revisions = Vec::new();
    for line in manifest
        .lines()
        .filter(|l| l.trim_start().starts_with("openshell-") && !l.contains("openshell-risk-guard"))
    {
        assert!(
            line.contains("git = \"https://github.com/NVIDIA/OpenShell\""),
            "{line}: OpenShell crates come from NVIDIA's public repository"
        );
        let rev = line
            .split("rev = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("{line}: pin the commit with rev"));
        assert_eq!(
            rev.len(),
            40,
            "{line}: pin a full 40-character commit, not a branch or a short hash"
        );
        assert!(
            rev.chars().all(|c| c.is_ascii_hexdigit()),
            "{line}: rev must be a commit hash"
        );
        revisions.push(rev.to_string());
    }
    assert!(!revisions.is_empty(), "no OpenShell dependencies found");
    revisions.dedup();
    assert_eq!(
        revisions.len(),
        1,
        "all openshell-* dependencies must use the same rev: {revisions:?}"
    );
}

fn pinned_rev() -> String {
    let manifest = manifest();
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("openshell-core"))
        .expect("openshell-core dependency");
    line.split("rev = \"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("rev")
        .to_string()
}

#[test]
fn the_pinned_commit_is_the_same_everywhere_it_is_named() {
    // The Cargo pin is the single source of truth. A script or a doc that names a different OpenShell commit would send a
    // reader to a CLI, chart or gateway that does not match the one Risk Guard is built against.
    let rev = pinned_rev();
    for file in [
        "scripts/prepare-rail-guard-demo-assets.sh",
        "docs/design.md",
        "docs/requirements.md",
        "docs/anomaly-detection.md",
    ] {
        let text =
            std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR"))).expect(file);
        assert!(
            text.contains(&rev),
            "{file} must name the pinned OpenShell commit {rev}"
        );
    }
}
