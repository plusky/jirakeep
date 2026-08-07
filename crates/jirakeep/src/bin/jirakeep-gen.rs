//! Dev/packaging tool: regenerate the committed man page and shell
//! completions from the `jirakeep` CLI definition. CI runs this and diffs
//! the output so the assets never drift. Built only with `--features gen`.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    let out = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from);
    match generate(&out) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

fn generate(out: &Path) -> std::io::Result<()> {
    let man_dir = out.join("man");
    let comp_dir = out.join("completions");
    std::fs::create_dir_all(&man_dir)?;
    std::fs::create_dir_all(&comp_dir)?;

    let mut cmd = jirakeep::config::command();
    cmd.build();
    std::fs::write(man_dir.join("jirakeep.1"), render_man(&cmd)?)?;
    for shell in [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
    ] {
        clap_complete::generate_to(shell, &mut cmd, "jirakeep", &comp_dir)?;
    }
    Ok(())
}

fn render_man(cmd: &clap::Command) -> std::io::Result<Vec<u8>> {
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    writeln!(
        buf,
        ".TH jirakeep 1 \"\" \"jirakeep {}\" \"General Commands Manual\"",
        cmd.get_version().unwrap_or_default()
    )?;
    man.render_name_section(&mut buf)?;
    render_synopsis(cmd, &mut buf)?;
    man.render_description_section(&mut buf)?;
    man.render_options_section(&mut buf)?;
    buf.write_all(EXIT_STATUS.as_bytes())?;
    render_environment(cmd, &mut buf)?;
    buf.write_all(FILES.as_bytes())?;
    buf.write_all(EXAMPLES.as_bytes())?;
    Ok(buf)
}

fn render_synopsis(cmd: &clap::Command, buf: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(buf, ".SH SYNOPSIS")?;
    writeln!(buf, "\\fBjirakeep\\fR")?;
    for arg in cmd.get_arguments() {
        if arg.get_id() == "help" || arg.get_id() == "version" {
            continue;
        }
        let long = arg
            .get_long()
            .expect("every jirakeep option is a long option")
            .replace('-', "\\-");
        let mut piece = format!("\\fB\\-\\-{long}\\fR");
        if arg.get_num_args().is_some_and(|n| n.takes_values()) {
            let metavar = arg
                .get_value_names()
                .and_then(|names| names.first().map(ToString::to_string))
                .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
            piece.push_str(&format!(" <{metavar}>"));
        }
        if arg.is_required_set() {
            writeln!(buf, "{piece}")?;
        } else {
            writeln!(buf, "[{piece}]")?;
        }
    }
    writeln!(buf, "[\\fB\\-h\\fR|\\fB\\-\\-help\\fR]")?;
    writeln!(buf, "[\\fB\\-V\\fR|\\fB\\-\\-version\\fR]")?;
    Ok(())
}

fn render_environment(cmd: &clap::Command, buf: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(buf, ".SH ENVIRONMENT")?;
    writeln!(
        buf,
        "Each variable is the fallback for one option; a command\\-line argument"
    )?;
    writeln!(
        buf,
        "always wins over the environment, and the built\\-in default applies when"
    )?;
    writeln!(buf, "neither is given.")?;
    for arg in cmd.get_arguments() {
        let Some(env) = arg.get_env() else { continue };
        let long = arg
            .get_long()
            .expect("every jirakeep option is a long option");
        writeln!(buf, ".TP")?;
        writeln!(buf, ".B {}", env.to_string_lossy())?;
        writeln!(
            buf,
            "Fallback for \\fB\\-\\-{}\\fR.",
            long.replace('-', "\\-")
        )?;
    }
    Ok(())
}

const EXIT_STATUS: &str = r".SH EXIT STATUS
.TP
.B 0
Clean shutdown.
.TP
.B 1
Startup or runtime failure: an unreadable policy, a key/email
misconfiguration, a Jira client or transport error.
.TP
.B 2
Command\-line usage error.
";

const FILES: &str = r".SH FILES
.TP
.I /etc/jirakeep/policy.toml
Worked example guard policy as installed by distribution packages; the
source tree and release archives ship it as
.IR examples/policy.toml .
The server reads a policy only when one is named with
.B \-\-policy
or
.BR JIRAKEEP_POLICY ;
without one the built\-in allow\-all default policy applies.
";

const EXAMPLES: &str = r".SH EXAMPLES
Serve a local MCP client over stdio:
.PP
.RS 4
.nf
jirakeep \-\-transport stdio \e
    \-\-jira\-server https://example.atlassian.net \e
    \-\-email user@example.com \e
    \-\-api\-key\-file ~/.config/jirakeep/api\-token \e
    \-\-policy /etc/jirakeep/policy.toml
.fi
.RE
.PP
Listen on HTTP (default, 127.0.0.1:8000), each client presenting its own
token in the API key header (email still required once issue tools call
Jira with Basic auth — use server\-held mode for a full credential pair):
.PP
.RS 4
.nf
jirakeep \-\-jira\-server https://example.atlassian.net \e
    \-\-policy /etc/jirakeep/policy.toml
.fi
.RE
";
