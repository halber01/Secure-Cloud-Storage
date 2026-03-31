use std::path::Path;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use crate::ops;
use crate::ops::Session;

pub async fn run<S>(stream: &mut S, session: &Session)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut rl = Editor::<(), _>::new().unwrap();
    let prompt = format!("{} > ", session.username);

    loop {
        match rl.readline(&prompt) {
            Ok(line) => {
                rl.add_history_entry(&line).expect("TODO: panic message");
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                match parts.as_slice() {
                    // handle commands here
                    ["help"] => { print_help(); }
                    ["exit"] | ["logout"] | ["quit"] => {
                        // TODO: tell server to invalidate session
                        println!("Goodbye.");
                        break;
                    }
                    ["list"] => {
                        match ops::list(stream, session).await {
                            Ok(files) => {
                                if files.is_empty() {
                                    println!("No files stored.");
                                }  else {
                                    println!("{:<40} {}", "Filename", "Version");
                                    println!("{}", "-".repeat(50));
                                    for (name, version) in files {
                                        println!("{:<40} v{}", name, version);
                                    }
                                }
                            }
                            Err(e) => eprintln!("List failed: {}", e),
                        }
                    }
                    ["upload", local, remote] => {
                        match ops::upload(stream, session, Path::new(local), remote).await {
                            Ok(()) => println!("✓ Uploaded '{}' as '{}'", local, remote),
                            Err(e) => eprintln!("Upload failed: {}", e),
                        }
                    }
                    ["upload", local] => {
                        let remote = Path::new(local)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy();
                        match ops::upload(stream, session, Path::new(local), &remote).await {
                            Ok(()) => println!("✓ Uploaded '{}'", local),
                            Err(e) => eprintln!("Upload failed: {}", e),
                        }
                    }

                    _ => eprintln!("Unknown command. Type 'help'."),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Ctrl+C — type 'exit' to quit");
            }
            Err(ReadlineError::Eof) => break, // Ctrl+D
            Err(e) => { eprintln!("Error: {}", e); break; }
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  upload <local_path> [remote_name]  Upload a file");
    println!("  download <remote_name> [local_path] Download a file");
    println!("  list                               List all files");
    println!("  delete <remote_name>               Delete a file");
    println!("  logout / exit / quit               Exit the shell");
}