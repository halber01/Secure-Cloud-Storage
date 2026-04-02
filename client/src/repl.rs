use crate::ops::{self, Session};
use rustyline::Editor;
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Helper};
use std::path::Path;

// Helper

struct CloudHelper {
    completer: FilenameCompleter,
}

impl Helper for CloudHelper {}
impl Highlighter for CloudHelper {}
impl Hinter for CloudHelper {
    type Hint = String;
}
impl Validator for CloudHelper {}

impl Completer for CloudHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // only complete after upload/download/cd commands
        let trimmed = line.trim_start();
        if trimmed.starts_with("upload")
            || trimmed.starts_with("cd")
            || trimmed.starts_with("download")
        {
            self.completer.complete(line, pos, ctx)
        } else {
            Ok((0, vec![]))
        }
    }
}

pub async fn run<S>(stream: &mut S, session: &Session)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .build();

    let helper = CloudHelper {
        completer: FilenameCompleter::new(),
    };

    let mut rl = Editor::with_config(config).unwrap();
    rl.set_helper(Some(helper));

    loop {
        let current_dir = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_string());
        let prompt = format!("{} [{}] > ", session.username, current_dir);
        match rl.readline(&prompt) {
            Ok(line) => {
                rl.add_history_entry(&line).expect("TODO: panic message");
                let parts: Vec<&str> = line.trim().split_whitespace().collect();
                match parts.as_slice() {
                    // handle commands here
                    ["help"] => {
                        print_help();
                    }
                    ["exit"] | ["logout"] | ["quit"] => {
                        // TODO: tell server to invalidate session
                        println!("Goodbye.");
                        break;
                    }
                    ["list"] => match ops::list(stream, session).await {
                        Ok(files) => {
                            if files.is_empty() {
                                println!("No files stored.");
                            } else {
                                println!("{:<40} Version", "Filename");
                                println!("{}", "-".repeat(50));
                                for (name, version) in files {
                                    println!("{:<40} v{}", name, version);
                                }
                            }
                        }
                        Err(e) => eprintln!("List failed: {}", e),
                    },
                    ["upload", local, remote] => {
                        match ops::upload_auto_version(stream, session, Path::new(local), remote)
                            .await
                        {
                            Ok(()) => println!("Uploaded '{}' as '{}'", local, remote),
                            Err(e) => eprintln!("Upload failed: {}", e),
                        }
                    }
                    ["upload", local] => {
                        let remote = Path::new(local)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy();
                        match ops::upload_auto_version(
                            stream,
                            session,
                            Path::new(local),
                            &remote,
                        )
                        .await
                        {
                            Ok(()) => println!("✓ Uploaded '{}'", local),
                            Err(e) => eprintln!("Upload failed: {}", e),
                        }
                    }
                    ["download", remote, local] => {
                        match ops::download(stream, session, remote, Path::new(local)).await {
                            Ok(()) => println!("Downloadded '{}'", local),
                            Err(e) => eprintln!("Download failed: {}", e),
                        }
                    }
                    ["download", remote] => {
                        match ops::download(stream, session, remote, Path::new(remote)).await {
                            Ok(()) => println!("Downloaded '{}'", remote),
                            Err(e) => eprintln!("Download failed: {}", e),
                        }
                    }
                    ["delete", remote] => {
                        println!("Are you sure you want to delete '{}'? [y/n]", remote);
                        match rl.readline("") {
                            Ok(resp) if resp.trim() == "y" => {
                                match ops::delete_file(stream, session, remote).await {
                                    Ok(()) => println!("Deleted '{}'", remote),
                                    Err(e) => eprintln!("Delete failed: {}", e),
                                }
                            }
                            _ => println!("Cancelled."),
                        }
                    }
                    ["ls"] => match std::fs::read_dir(".") {
                        Ok(entries) => {
                            let mut names: Vec<String> = entries
                                .flatten()
                                .map(|e| e.file_name().to_string_lossy().to_string())
                                .collect();
                            names.sort();
                            for name in names {
                                println!("{}", name);
                            }
                        }
                        Err(e) => eprintln!("ls failed: {}", e),
                    },
                    ["pwd"] => match std::env::current_dir() {
                        Ok(path) => println!("{}", path.display()),
                        Err(e) => eprintln!("pwd failed: {}", e),
                    },
                    ["cd", path] => {
                        if let Err(e) = std::env::set_current_dir(path) {
                            eprintln!("cd failed: {}", e);
                        }
                    }
                    _ => eprintln!("Unknown command. Type 'help'."),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Ctrl+C — type 'exit' to quit");
            }
            Err(ReadlineError::Eof) => break, // Ctrl+D
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  upload <local_path> [remote_name]   Upload a file");
    println!("  download <remote_name> [local_path] Download a file");
    println!("  list                                List all files");
    println!("  delete <remote_name>                Delete a file");
    println!("  ls                                  List local files");
    println!("  pwd                                 Show current directory");
    println!("  cd <path>                           Change directory");
    println!("  logout / exit / quit                Exit the shell");
}
