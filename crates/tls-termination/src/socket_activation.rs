use crate::{FpError, FpResult};
use std::net::TcpListener;
use std::os::fd::{FromRawFd, RawFd};

pub const SYSTEMD_LISTEN_PID_ENV: &str = "LISTEN_PID";
pub const SYSTEMD_LISTEN_FDS_ENV: &str = "LISTEN_FDS";
pub const SYSTEMD_LISTEN_FDNAMES_ENV: &str = "LISTEN_FDNAMES";
pub const SYSTEMD_LISTEN_FD_START: RawFd = 3;

#[derive(Debug)]
pub struct InheritedTcpListener {
    pub fd: RawFd,
    pub name: Option<String>,
    pub listener: TcpListener,
}

pub fn clear_systemd_socket_activation_env() {
    std::env::remove_var(SYSTEMD_LISTEN_PID_ENV);
    std::env::remove_var(SYSTEMD_LISTEN_FDS_ENV);
    std::env::remove_var(SYSTEMD_LISTEN_FDNAMES_ENV);
}

pub fn acquire_systemd_inherited_tcp_listeners() -> FpResult<Vec<InheritedTcpListener>> {
    let listen_pid_raw = std::env::var(SYSTEMD_LISTEN_PID_ENV).ok();
    let listen_fds_raw = std::env::var(SYSTEMD_LISTEN_FDS_ENV).ok();
    let listen_fd_names_raw = std::env::var(SYSTEMD_LISTEN_FDNAMES_ENV).ok();

    let listeners = acquire_systemd_inherited_tcp_listeners_from_values(
        listen_pid_raw.as_deref(),
        listen_fds_raw.as_deref(),
        listen_fd_names_raw.as_deref(),
        std::process::id(),
        SYSTEMD_LISTEN_FD_START,
    )?;

    clear_systemd_socket_activation_env();
    Ok(listeners)
}

fn acquire_systemd_inherited_tcp_listeners_from_values(
    listen_pid_raw: Option<&str>,
    listen_fds_raw: Option<&str>,
    listen_fd_names_raw: Option<&str>,
    expected_pid: u32,
    fd_start: RawFd,
) -> FpResult<Vec<InheritedTcpListener>> {
    let listen_pid = parse_required_u32(listen_pid_raw, SYSTEMD_LISTEN_PID_ENV)?;
    if listen_pid != expected_pid {
        return Err(FpError::invalid_configuration(format!(
            "LISTEN_PID does not match current process id for systemd socket activation: expected {expected_pid}, got {listen_pid}"
        )));
    }

    let listen_fds = parse_required_usize(listen_fds_raw, SYSTEMD_LISTEN_FDS_ENV)?;
    if listen_fds == 0 {
        return Err(FpError::invalid_configuration(
            "LISTEN_FDS must be >= 1 for systemd socket activation",
        ));
    }

    let listen_fd_names = parse_optional_fd_names(listen_fd_names_raw, listen_fds)?;
    let max_fd = fd_start as i64 + listen_fds as i64 - 1;
    if max_fd > i32::MAX as i64 {
        return Err(FpError::invalid_configuration(format!(
            "LISTEN_FDS value {listen_fds} exceeds supported descriptor range for systemd socket activation"
        )));
    }

    let mut listeners = Vec::with_capacity(listen_fds);
    for (idx, name) in listen_fd_names.into_iter().enumerate() {
        let fd = fd_start + idx as RawFd;
        let listener = unsafe { TcpListener::from_raw_fd(fd) };
        if let Err(err) = listener.local_addr() {
            return Err(FpError::invalid_configuration(format!(
                "inherited fd {fd} is not a valid TCP listener for systemd socket activation: {err}"
            )));
        }
        if let Err(err) = listener.set_nonblocking(true) {
            return Err(FpError::invalid_configuration(format!(
                "inherited fd {fd} could not be set nonblocking for systemd socket activation: {err}"
            )));
        }
        listeners.push(InheritedTcpListener { fd, name, listener });
    }

    Ok(listeners)
}

fn parse_required_u32(raw: Option<&str>, env_var: &str) -> FpResult<u32> {
    let value = raw.ok_or_else(|| {
        FpError::invalid_configuration(format!(
            "missing required env var {env_var} for systemd socket activation"
        ))
    })?;
    value.parse::<u32>().map_err(|_| {
        FpError::invalid_configuration(format!(
            "invalid {env_var} value for systemd socket activation: {value}"
        ))
    })
}

fn parse_required_usize(raw: Option<&str>, env_var: &str) -> FpResult<usize> {
    let value = raw.ok_or_else(|| {
        FpError::invalid_configuration(format!(
            "missing required env var {env_var} for systemd socket activation"
        ))
    })?;
    value.parse::<usize>().map_err(|_| {
        FpError::invalid_configuration(format!(
            "invalid {env_var} value for systemd socket activation: {value}"
        ))
    })
}

fn parse_optional_fd_names(
    raw: Option<&str>,
    expected_count: usize,
) -> FpResult<Vec<Option<String>>> {
    match raw {
        None => Ok(vec![None; expected_count]),
        Some("") => Ok(vec![None; expected_count]),
        Some(value) => {
            let names: Vec<Option<String>> = value
                .split(':')
                .map(|part| {
                    if part.is_empty() {
                        None
                    } else {
                        Some(part.to_string())
                    }
                })
                .collect();
            if names.len() != expected_count {
                return Err(FpError::invalid_configuration(format!(
                    "LISTEN_FDNAMES count does not match LISTEN_FDS for systemd socket activation: expected {expected_count}, got {}",
                    names.len()
                )));
            }
            Ok(names)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_proxy_core::error::ErrorKind;
    use std::io::Write;
    use std::net::TcpListener;
    use std::os::fd::IntoRawFd;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn missing_listen_pid_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            None,
            Some("1"),
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("missing LISTEN_PID must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "missing required env var LISTEN_PID for systemd socket activation"
        );
    }

    #[test]
    fn invalid_listen_pid_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("abc"),
            Some("1"),
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("invalid LISTEN_PID must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "invalid LISTEN_PID value for systemd socket activation: abc"
        );
    }

    #[test]
    fn mismatched_listen_pid_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("999"),
            Some("1"),
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("mismatched LISTEN_PID must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "LISTEN_PID does not match current process id for systemd socket activation: expected 42, got 999"
        );
    }

    #[test]
    fn missing_listen_fds_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            None,
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("missing LISTEN_FDS must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "missing required env var LISTEN_FDS for systemd socket activation"
        );
    }

    #[test]
    fn invalid_listen_fds_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            Some("x"),
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("invalid LISTEN_FDS must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "invalid LISTEN_FDS value for systemd socket activation: x"
        );
    }

    #[test]
    fn zero_listen_fds_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            Some("0"),
            None,
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("zero LISTEN_FDS must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "LISTEN_FDS must be >= 1 for systemd socket activation"
        );
    }

    #[test]
    fn fd_name_count_mismatch_is_deterministic_invalid_configuration() {
        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            Some("2"),
            Some("https"),
            42,
            SYSTEMD_LISTEN_FD_START,
        )
        .expect_err("fd name count mismatch must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "LISTEN_FDNAMES count does not match LISTEN_FDS for systemd socket activation: expected 2, got 1"
        );
    }

    #[test]
    fn non_socket_inherited_fd_is_deterministic_invalid_configuration() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fp-systemd-socket-activation-non-socket-{}.txt",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = std::fs::File::create(path).expect("create temp file");
        writeln!(file, "not a socket").expect("write file");
        let fd = file.into_raw_fd();

        let err = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            Some("1"),
            None,
            42,
            fd,
        )
        .expect_err("non-socket fd must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert!(err.message.contains(&format!("inherited fd {fd}")));
        assert!(err
            .message
            .contains("is not a valid TCP listener for systemd socket activation"));
    }

    #[test]
    fn tcp_listener_fd_is_adapted_with_deterministic_order_and_name() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let fd = listener.into_raw_fd();

        let inherited = acquire_systemd_inherited_tcp_listeners_from_values(
            Some("42"),
            Some("1"),
            Some("https"),
            42,
            fd,
        )
        .expect("valid inherited listener");

        assert_eq!(inherited.len(), 1);
        assert_eq!(inherited[0].fd, fd);
        assert_eq!(inherited[0].name.as_deref(), Some("https"));
        assert_eq!(
            inherited[0].listener.local_addr().expect("local addr"),
            addr
        );
    }

    #[test]
    fn public_acquisition_reports_missing_env_deterministically() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_systemd_socket_activation_env();

        let err = acquire_systemd_inherited_tcp_listeners().expect_err("missing env must fail");
        assert_eq!(err.kind, ErrorKind::InvalidConfiguration);
        assert_eq!(
            err.message,
            "missing required env var LISTEN_PID for systemd socket activation"
        );
    }
}
