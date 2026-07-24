use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tit_cde::app::run().await
}
