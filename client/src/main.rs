mod config;
mod ops;

use clap::{Parser, Subcommand};
use std::path::Path;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

#[derive(Parser)]
#[command(name = "cloud", about = "Secure cloud storage client")]
struct Cli {
    #[arg(long, default_value = config::SERVER_ADDR)]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register {
        username: String,
    },
    Upload {
        username: String,
        local_path: String,
        remote_name: String,
        version: u64,
    },
    Download {
        username: String,
        remote_name: String,
        local_path: String,
    },
    List {
        username: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut stream = match ops::connect(&cli.server).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Could not connect to server: {}", e);
            return;
        }
    };
    match cli.command {
        Commands::Register { username } => {
            let password = rpassword::prompt_password("Password: ").unwrap();
            match ops::register(&mut stream, &username, &password).await {
                Ok(()) => println!("Registered successfully as '{}'", username),
                Err(e) => eprintln!("Registration failed: {}", e),
            }
        }
        Commands::Upload {
            username,
            local_path,
            remote_name,
            version,
        } => {
            let session = match prompt_and_login(&mut stream, &username).await {
                Some(s) => s,
                None => return,
            };
            match ops::upload(
                &mut stream,
                &session,
                Path::new(&local_path),
                &remote_name,
                version,
            )
            .await
            {
                Ok(()) => println!("Uploaded '{}' as '{}'", local_path, remote_name),
                Err(e) => eprintln!("Upload failed: {}", e),
            }
        }
        Commands::Download {
            username,
            remote_name,
            local_path,
        } => {
            let session = match prompt_and_login(&mut stream, &username).await {
                Some(s) => s,
                None => return,
            };
            match ops::download(&mut stream, &session, &remote_name, Path::new(&local_path)).await {
                Ok(()) => println!("Downloaded '{}' as '{}'", local_path, remote_name),
                Err(e) => eprintln!("Download failed: {}", e),
            }
        }
        Commands::List { username } => {
            let session = match prompt_and_login(&mut stream, &username).await {
                Some(s) => s,
                None => return,
            };
            match ops::list(&mut stream, &session).await {
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
            }
        }
    }
}

async fn prompt_and_login(
    stream: &mut TlsStream<TcpStream>,
    username: &str,
) -> Option<ops::Session> {
    let password = rpassword::prompt_password("Password: ").unwrap();
    match ops::login(stream, username, &password).await {
        Ok(session) => {
            println!("Logged in as '{}'", session.username);
            Some(session)
        }
        Err(e) => {
            eprintln!("Login failed: {}", e);
            None
        }
    }
}
