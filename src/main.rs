fn main() {
    if let Err(error) = burpcli::cli::run() {
        eprintln!("burpcli: {error:#}");
        std::process::exit(1);
    }
}
