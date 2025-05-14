use crate::*;
use anyhow::{Context, Result};
use interprocess::local_socket::{prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions, Name};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const SOCKET_PATH: &str = "/tmp/por.sock";

fn handle_client(
    stream: &interprocess::local_socket::Stream,
    merkle_tree: &MerkleTree,
    nonces: &Vec<u64>,
    ledger: &Ledger,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut writer = stream;

    let mut buffer = String::new();
    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                // prove inclusion with the received hash
                let hash = buffer.trim(); // Remove newline character

                let inclusion_proof =
                    prove_user_inclusion_by_hash(hash.to_string(), merkle_tree, nonces, ledger)?;

                // write the proof into the file and send the file path back to the client
                let proof_path = format!(
                    "{}/inclusion_proofs/inclusion_proof_{}.json",
                    std::env::current_dir()?.display(),
                    hash
                );
                println!("Writing inclusion proof to: {}", proof_path);
                let inclusion_proof_json = serde_json::to_string(&inclusion_proof)?; // Propagate serialization errors
                std::fs::write(proof_path.clone(), inclusion_proof_json)?; // Propagate file writing errors

                // Send the file path back to the client with a newline
                writer
                    .write_all(format!("{}\n", proof_path).as_bytes())
                    .context("Failed to write to client")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // This can happen with non-blocking, but we're using blocking by default.
                // For a simple example, we'll treat it as an error or continue.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }
    }
    Ok(())
}

pub fn create_local_server<'a>(
    merkle_tree: MerkleTree,
    nonces: Vec<u64>,
    ledger: Ledger,
) -> Result<()> {
    let socket_name: Name<'_> = SOCKET_PATH.to_fs_name::<GenericFilePath>()?;

    // This is important because bind will fail if the file already exists.
    if Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH)
            .with_context(|| format!("Failed to remove existing socket file: {}", SOCKET_PATH))?;
        log_info!("Removed existing socket file: {}", SOCKET_PATH);
    }

    let merkle_tree = Arc::new(merkle_tree);
    let nonces = Arc::new(nonces);
    let ledger = Arc::new(ledger);

    let listener_options = ListenerOptions::new().name(socket_name);

    let listener = match listener_options.create_sync() {
        Ok(listener) => {
            log_success!("Server listening on socket: {}", SOCKET_PATH);
            listener
        }
        Err(e) => {
            // If it's AddrInUse, it might be a race condition or permissions issue
            // even after trying to remove the file.
            log_error!(
                "Failed to create listener: {}. Socket path: {}",
                e,
                SOCKET_PATH
            );
            if e.kind() == std::io::ErrorKind::AddrInUse {
                log_error!(
                    "Address already in use. Ensure no other instance is running or the socket file '{}' was properly cleaned.",
                    SOCKET_PATH
                );
            }
            return Err(e).context(format!(
                "Failed to create listener for socket: {}",
                SOCKET_PATH
            ));
        }
    };

    for connection_result in listener.incoming() {
        match connection_result {
            Ok(stream) => {
                // Spawn a new thread to handle each client.
                // For a production daemon, consider using a thread pool or async runtime.
                let merkle_tree = Arc::clone(&merkle_tree);
                let nonces = Arc::clone(&nonces);
                let ledger = Arc::clone(&ledger);

                thread::spawn(move || {
                    if let Err(e) = handle_client(&stream, &merkle_tree, &nonces, &ledger) {
                        log_error!("Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                log_error!("Failed to accept incoming connection: {}", e);
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // This shouldn't happen with blocking `incoming()` by default.
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                log_error!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}

pub fn send_hash_to_server(hash: &str) -> Result<()> {
    // 1. Create a connection to the server.
    let socket_name: Name<'_> = SOCKET_PATH.to_fs_name::<GenericFilePath>()?;
    let mut stream = interprocess::local_socket::Stream::connect(socket_name)
        .with_context(|| {
            // the server stopped running, remove the socket file
            let _ = std::fs::remove_file(SOCKET_PATH)
                .with_context(|| format!("Failed to remove socket file: {}", SOCKET_PATH));
            format!("Failed to connect to socket: {}, so it was deleted.
            The prover server probably stopped running. If you want to prove without the server, run the same command again", SOCKET_PATH)
        })?;

    // 2. Send the hash as a line of text.
    let message = format!("{}\n", hash);
    stream
        .write_all(message.as_bytes())
        .with_context(|| format!("Failed to send message to server: {}", message))?;

    // 3. wait for the response from the server (the file path)
    let mut reader = BufReader::new(&stream);
    let mut buffer = String::new();
    reader
        .read_line(&mut buffer)
        .with_context(|| format_error("Failed to read response from server"))?;

    if !buffer.starts_with("/") {
        // should be a file path
        return Err(anyhow::anyhow!("Invalid response from server: {}", buffer));
    }

    // 4. Print the file path
    log_success!("Inclusion proof created at: {}", buffer.trim());

    Ok(())
}
