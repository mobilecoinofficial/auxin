use std::process::Command;
fn main() {
    // Make git hash available to the program for versioning. 
    let output = Command::new("git").args(&["rev-parse", "--short", "HEAD"]).output().expect("Could not run 'git' in the build process to retrieve a git hash for versioning.");
    let git_hash = String::from_utf8(output.stdout).expect("Failed to get a git hash from stdout from the 'git' command.");
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}