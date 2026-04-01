mod config;
mod ops;
mod repl;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cloud", about = "Secure cloud storage client")]
struct Cli {
    #[arg(long)]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Register { username: String },
    Login { username: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = config::load_config();
    let addr = cli
        .server
        .unwrap_or_else(|| format!("{}:{}", config.server.address, config.server.port));
    let mut stream = match ops::connect(&addr).await {
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
        Commands::Login { username } => {
            let mut stream = match ops::connect(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Could not connect: {}", e);
                    return;
                }
            };
            let password = rpassword::prompt_password("Password: ").unwrap();
            match ops::login(&mut stream, &username, &password).await {
                Ok(session) => {
                    println!("✓ Logged in as '{}'. Type 'help' for commands.", username);
                    repl::run(&mut stream, &session).await;
                }
                Err(e) => eprintln!("Login failed: {}", e),
            }
        }
    }
}
