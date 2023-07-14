use vergen::EmitBuilder;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Emit the instructions
    EmitBuilder::builder().all_build().all_git().git_sha(true).fail_on_error().emit()?;
    Ok(())
}
