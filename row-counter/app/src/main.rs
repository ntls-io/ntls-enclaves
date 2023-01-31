use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(default_value = "../sample.json")]
    path: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let input_string = std::fs::read_to_string(cli.path)?;
    row_counter_module::run(&input_string)?;
    Ok(())
}
