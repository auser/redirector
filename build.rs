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

    Ok(())
}
