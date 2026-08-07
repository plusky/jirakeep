//! Smoke: the shipped binary answers --help / --version without contacting Jira.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_jirakeep"))
}

#[test]
fn help_exits_zero_and_names_jira() {
    let out = bin().arg("--help").output().expect("spawn jirakeep --help");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("jira"),
        "help should mention jira: {stdout}"
    );
    assert!(stdout.contains("--jira-server"));
    assert!(stdout.contains("--policy"));
}

#[test]
fn version_exits_zero() {
    let out = bin()
        .arg("--version")
        .output()
        .expect("spawn jirakeep --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("jirakeep"));
}
