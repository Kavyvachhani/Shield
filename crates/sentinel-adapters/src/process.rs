//! Process spawning that stays invisible on Windows.
//!
//! The desktop shell is built with `windows_subsystem = "windows"`, so it owns
//! no console. When such a process starts a console program, Windows creates a
//! console for the child — a black window that appears on screen and vanishes.
//! Engine discovery probes five scanners, each with a `where` lookup, and every
//! scan then spawns the engines themselves, so the user sees a burst of
//! flashing windows that reads as the application malfunctioning.
//!
//! `CREATE_NO_WINDOW` suppresses that console. Redirected stdout and stderr are
//! unaffected, so output is still captured exactly as before.
//!
//! Both constructors are no-ops off Windows, which keeps the call sites free of
//! `#[cfg]` noise.

use std::ffi::OsStr;

/// Win32 process creation flag: run the child without allocating a console.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A blocking [`std::process::Command`] that shows no console window.
pub fn std_command(program: impl AsRef<OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// An async [`tokio::process::Command`] that shows no console window.
pub fn async_command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrappers must stay ordinary commands: the flag is the only
    /// difference, so anything spawnable before is still spawnable now.
    #[test]
    fn a_wrapped_command_still_runs_and_captures_output() {
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("cmd", &["/C", "echo sentinel"])
        } else {
            ("echo", &["sentinel"])
        };
        let out = std_command(program).args(args).output().expect("command must run");
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("sentinel"));
    }

    #[tokio::test]
    async fn the_async_wrapper_captures_output_too() {
        let (program, args): (&str, &[&str]) = if cfg!(windows) {
            ("cmd", &["/C", "echo sentinel"])
        } else {
            ("echo", &["sentinel"])
        };
        let out = async_command(program).args(args).output().await.expect("command must run");
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("sentinel"));
    }
}
