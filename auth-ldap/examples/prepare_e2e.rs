// Build the same subject used by the live tests before their runtime deadline starts.
#[path = "../tests/support/subject.rs"]
mod subject;

fn main() {
    let _ = subject::build_real_binaries();
}
