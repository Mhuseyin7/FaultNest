use clap::{Parser, Subcommand};
use faultnest_core as core;
use std::{path::PathBuf, process::ExitCode};
#[derive(Parser)]
#[command(name = "faultnest", version, about = "Capture. Isolate. Replay.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Init,
    Capture {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        request: Option<PathBuf>,
    },
    Preview,
    Inspect {
        bundle: PathBuf,
    },
    Verify {
        bundle: PathBuf,
    },
    Replay {
        bundle: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    Down {
        target: PathBuf,
    },
    Doctor,
    Minimize {
        bundle: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Test {
        bundle: PathBuf,
    },
}
fn cfg() -> core::Result<core::Config> {
    core::load_config(&PathBuf::from("faultnest.yml"))
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("faultnest: {e}");
            ExitCode::from(2)
        }
    }
}
fn run() -> core::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => {
            let p = PathBuf::from("faultnest.yml");
            if p.exists() {
                Err(core::Error::Config("faultnest.yml already exists".into()))
            } else {
                std::fs::write(&p,"version: 1\napplication:\n  name: my-app\ncapture:\n  repository: true\n  logs: []\nenvironment:\n  allow_names: [NODE_ENV]\nredaction:\n  emails: true\n  ip_addresses: true\n  paths: true\nreplay:\n  command:\n    name: test\n    executable: cargo\n    args: [test]\n  network: OFF\n").map_err(|e|core::Error::Config(e.to_string())).map(|_|println!("Created faultnest.yml"))
            }
        }
        Cmd::Capture { output, request } => {
            let c = cfg()?;
            let out = output
                .unwrap_or_else(|| PathBuf::from(format!("issue-{}.faultnest", chrono_date())));
            let m = core::capture(
                &std::env::current_dir().unwrap(),
                &c,
                &out,
                request.as_deref(),
            )?;
            println!(
                "Captured {} ({} entries, {} redactions)",
                out.display(),
                m.entries.len(),
                m.redaction_summary.values().sum::<u64>()
            );
            Ok(())
        }
        Cmd::Preview => {
            let c = cfg()?;
            println!(
                "FaultNest Preview\nGit metadata            {}\nLockfiles/manifests     {}\nConfigured log files    {}\nEnvironment values      0 (names only)\nNetwork policy           {:?}",
                c.capture.repository,
                core::dependency_files(&std::env::current_dir().unwrap()).len(),
                c.capture.logs.len(),
                c.replay.network
            );
            Ok(())
        }
        Cmd::Inspect { bundle } | Cmd::Verify { bundle } => {
            let m = core::inspect(&bundle)?;
            println!(
                "Valid FaultNest bundle\nApplication: {}\nCreated: {}\nPlatform: {}/{}\nEntries: {}\nRedactions: {}",
                m.application.name,
                m.created_at,
                m.platform,
                m.architecture,
                m.entries.len(),
                m.redaction_summary.values().sum::<u64>()
            );
            Ok(())
        }
        Cmd::Replay { bundle, yes } => replay(bundle, yes),
        Cmd::Down { target } => {
            if target.exists() {
                std::fs::remove_dir_all(&target).map_err(|e| core::Error::Replay(e.to_string()))?;
                println!("Removed replay workspace {}", target.display());
            } else {
                println!("No local replay workspace found.")
            }
            Ok(())
        }
        Cmd::Minimize { bundle, output } => {
            core::verify(&bundle)?;
            Err(core::Error::Replay(format!(
                "minimize is unavailable: no reproduction oracle is implemented (would have written {})",
                output.display()
            )))
        }
        Cmd::Test { bundle } => {
            core::verify(&bundle)?;
            Err(core::Error::Replay(
                "test generation is unavailable: a proven replay assertion is required".into(),
            ))
        }
        Cmd::Doctor => {
            for x in ["git", "docker"] {
                let ok = std::process::Command::new(x)
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                println!("{x:10} {}", if ok { "available" } else { "unavailable" });
            }
            println!("FaultNest {}", core::VERSION);
            Ok(())
        }
    }
}
fn chrono_date() -> String {
    let o = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Date -Format yyyy-MM-dd"])
        .output()
        .ok();
    o.map(|x| String::from_utf8_lossy(&x.stdout).trim().to_string())
        .unwrap_or_else(|| "bundle".into())
}
fn replay(bundle: PathBuf, yes: bool) -> core::Result<()> {
    let m = core::verify(&bundle)?;
    println!(
        "Replay plan\nRepository: {}\nRuntime: captured commands\nCommand: {} {}\nNetwork: {:?}\nTemporary workspace: enabled",
        m.git
            .as_ref()
            .map(|g| g.commit.as_str())
            .unwrap_or("not captured"),
        m.replay.command.executable,
        m.replay.command.args.join(" "),
        m.replay.network
    );
    if !yes {
        return Err(core::Error::Replay(
            "confirmation required; rerun with --yes for noninteractive replay".into(),
        ));
    }
    let work = std::env::temp_dir().join(format!("faultnest-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| core::Error::Replay(e.to_string()))?;
    core::extract(&bundle, &work)?;
    let source = core::reconstruct_source(&m, &work)?;
    let failed = if let Some(policy) = &m.replay.container {
        core::container_replay(
            policy,
            &m.replay.network,
            &source,
            &m.replay.command,
            m.replay.timeout_seconds,
        )?
    } else {
        core::run_trigger(&m.replay.command, &source, m.replay.timeout_seconds)?
    };
    println!(
        "{}\nWorkspace: {}",
        if failed {
            "REPRODUCED"
        } else {
            "NOT_REPRODUCED"
        },
        work.display()
    );
    Ok(())
}
