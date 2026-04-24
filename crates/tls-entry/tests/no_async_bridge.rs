use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/tls-entry -> crates -> repo root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .expect("repo root")
}

fn scan_dir_for_markers(dir: &Path, markers: &[&str], hits: &mut Vec<(PathBuf, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|n| n == std::ffi::OsStr::new("target"))
        {
            continue;
        }
        if path.is_dir() {
            scan_dir_for_markers(&path, markers, hits);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for &marker in markers {
            if contents.contains(marker) {
                hits.push((path.clone(), marker.to_string()));
            }
        }
    }
}

#[test]
fn repo_does_not_use_sync_async_bridge_helpers() {
    let root = repo_root();
    let mut hits = Vec::new();
    let marker_a = ["block", "_in", "_place"].concat();
    let marker_b = ["new", "_current", "_thread"].concat();

    let marker_spawn_blocking = ["tokio", "::", "task", "::", "spawn", "_", "blocking"].concat();
    let marker_std_tcp = ["std", "::", "net", "::", "Tcp", "Stream"].concat();
    let marker_std_udp = ["std", "::", "net", "::", "Udp", "Socket"].concat();
    let marker_unix_stream = [
        "std", "::", "os", "::", "unix", "::", "net", "::", "Unix", "Stream",
    ]
    .concat();
    let marker_unix_datagram = [
        "std", "::", "os", "::", "unix", "::", "net", "::", "Unix", "Datagram",
    ]
    .concat();
    let marker_unix_listener = [
        "std", "::", "os", "::", "unix", "::", "net", "::", "Unix", "Listener",
    ]
    .concat();
    let marker_runtime_new = ["tokio", "::", "runtime", "::", "Runtime", "::", "new"].concat();
    let marker_runtime_builder = ["tokio", "::", "runtime", "::", "Builder"].concat();
    let marker_handle_block_on = ["Handle", "::", "block", "_", "on"].concat();

    let markers = [
        &marker_a[..],
        &marker_b[..],
        &marker_spawn_blocking[..],
        &marker_std_tcp[..],
        &marker_std_udp[..],
        &marker_unix_stream[..],
        &marker_unix_datagram[..],
        &marker_unix_listener[..],
        &marker_runtime_new[..],
        &marker_runtime_builder[..],
        &marker_handle_block_on[..],
    ];

    scan_dir_for_markers(&root.join("bin"), &markers, &mut hits);
    scan_dir_for_markers(&root.join("crates"), &markers, &mut hits);

    assert!(
        hits.is_empty(),
        "found forbidden async-bridge markers: {hits:?}"
    );
}
