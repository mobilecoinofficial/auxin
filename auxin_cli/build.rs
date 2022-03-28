use std::process::Command;
fn main() {
    // Make git hash available to the program for versioning. 
    let output = Command::new("git").args(&["rev-parse", "--short", "HEAD"]).output().expect("Could not run 'git rev-parse' in the build process to retrieve a git hash for versioning.");
    let git_hash = String::from_utf8(output.stdout).expect("Failed to get a git hash from stdout from the 'git' command.");

    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    let output = Command::new("git").args(&["status", "--short"]).output().expect("Could not run 'git status' in the build process to retrieve a git hash for versioning.");
    let modified_list = String::from_utf8(output.stdout).expect("Failed to ascertain repository-dirty status from the 'git' command.");
    if modified_list.len() > 0 { 
        println!("cargo:rustc-cfg=git_untracked");
    }
}