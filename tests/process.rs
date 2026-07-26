use std::env;
use std::process::Command;

pub(crate) fn current_exe() -> Command {
    match (
        env::var_os("TIT_TEST_RUNNER"),
        env::var_os("TIT_TEST_EXECUTABLE"),
    ) {
        (Some(runner), Some(executable)) => {
            let mut command = Command::new(runner);
            command.arg(executable);
            command
        }
        (None, None) => Command::new(env::current_exe().expect("find the current test executable")),
        _ => panic!("the test runner and test executable must be set together"),
    }
}
