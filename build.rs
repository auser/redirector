use std::process::Command;

use vergen_git2::{BuildBuilder, Emitter, Git2Builder, SysinfoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::all_build()?;
    let si = SysinfoBuilder::all_sysinfo()?;
    let git2 = Git2Builder::all_git()?;

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&si)?
        .add_instructions(&git2)?
        .emit()?;

    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    if let Ok(output) = output {
        let git_hash = String::from_utf8(output.stdout).unwrap();
        println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    }

    // Set build time
    let now = chrono::Utc::now();
    println!(
        "cargo:rustc-env=BUILD_TIME={}",
        now.format("%Y-%m-%d %H:%M:%S UTC")
    );

    Ok(())
}
