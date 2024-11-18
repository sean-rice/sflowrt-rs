//! `reedline_repl_rs`Minimal example

use reedline_repl_rs::clap::{Arg, ArgMatches, Command};
use reedline_repl_rs::{Repl, Result};
use sflowrt_rs_flow::key::{
    key_parser::{finish_nom_parse, parse_key_definition},
    KeyDefinition,
};

/// Parse an sFlow-RT Flow key definition.
fn parse_key<T>(args: ArgMatches, _context: &mut T) -> anyhow::Result<Option<String>> {
    let input: String = args.get_one::<String>("key-definition").unwrap().to_owned();
    let (leftover, definition): (String, KeyDefinition) =
        finish_nom_parse(parse_key_definition(&input))?;
    anyhow::ensure!(
        leftover.is_empty(),
        format!("Parsing failed.\n\nRemaining input: {leftover}\n\nParsed: {definition:?}")
    );
    Ok(Some(format!("{definition:?}")))
}

fn main() -> Result<()> {
    let mut repl = Repl::new(())
        .with_name("sflowrt-rs-cli")
        .with_version("v0.1.0")
        .with_description("sFlow-RT Rust CLI")
        //.with_banner("Welcome to MyApp")
        .with_command(
            Command::new("parse-key")
                .arg(Arg::new("key-definition").required(true))
                .about("Parse an sFlow-RT Flow key definition."),
            parse_key,
        );
    repl.run()
}
