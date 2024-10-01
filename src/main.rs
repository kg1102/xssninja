mod opt;
mod wordlist;
mod xss_checker;
mod utils;

use opt::Opt;
use wordlist::fetch_wordlist;
use xss_checker::check_xss;
use utils::{read_lines, read_stdin_lines, print_error};

use colored::*;
use reqwest::Client;
use structopt::StructOpt;
use futures::stream::{self, StreamExt};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    if opt.verbose {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Error)
            .init();
    } else {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Off)
            .init();
    }

    println!("{}", "XSS NINJA - Starting scan...".green().bold());

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("Failed to build HTTP client");

    let wordlist_url = "https://raw.githubusercontent.com/kg1102/xssninja/refs/heads/main/wordlists/sam-cc-parameters-mixedcase-all.txt";
    let wordlist = match fetch_wordlist(wordlist_url).await {
        Ok(list) => list,
        Err(e) => {
            print_error(opt.verbose, "Error downloading wordlist", &e);
            return;
        }
    };
    let wordlist = Arc::new(wordlist);

    let domains: Vec<String> = if let Some(file_path) = opt.file {
        match read_lines(&file_path) {
            Ok(lines) => lines.filter_map(|line| line.ok()).collect(),
            Err(e) => {
                print_error(opt.verbose, &format!("Error reading file: {}", file_path), &e);
                return;
            }
        }
    } else {
        read_stdin_lines().filter_map(|line| line.ok()).collect()
    };

    let verbose = opt.verbose;

    stream::iter(domains)
        .map(|domain| {
            let client = client.clone();
            let verbose = verbose;
            let wordlist = Arc::clone(&wordlist);
            async move {
                let domain = domain.trim().to_string();
                if domain.is_empty() {
                    return;
                }
                check_xss(&client, &domain, verbose, &wordlist).await;
            }
        })
        .buffer_unordered(opt.concurrency)
        .for_each(|_| async {})
        .await;
}
