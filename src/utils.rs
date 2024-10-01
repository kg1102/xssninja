use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use urlencoding::encode;
use regex::Regex;
use scraper::{Html, Selector};
use url::Url;
use log::info;

use colored::Colorize;

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn read_stdin_lines() -> io::Lines<io::BufReader<io::Stdin>> {
    io::BufReader::new(io::stdin()).lines()
}

pub fn print_error(verbose: bool, msg: &str, err: &dyn std::fmt::Display) {
    if verbose {
        eprintln!("{}: {}", msg, err);
    }
    // nao faz nada se verbose for false
}

pub fn build_url_with_pairs(base_url: &Url, pairs: &[(String, String)]) -> Option<String> {
    let mut url = base_url.clone();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs.iter().map(|(k, v)| (k, v)));
    Some(url.into())
}

pub fn sanitize_payload(payload: &str, body: &str) -> bool {
    let encoded_payload = encode(payload);
    let binding = encoded_payload.to_string();

    let sanitization_patterns = vec![
        (payload, "Raw Payload Present"),
        (binding.as_str(), "URL Encoded Payload"),
        ("&lt;", "HTML Escaped '<'"),
        ("&gt;", "HTML Escaped '>'"),
        ("&quot;", "HTML Escaped '\"'"),
        ("&#x27;", "HTML Escaped '''"),
        ("&#x2F;", "HTML Escaped '/'"),
        ("<script>", "Script Tag Removed"),
        ("</script>", "Script Tag Removed"),
        (r"(?i)encodeURIComponent\(", "JavaScript Encoding"),
        (r"(?i)escape\(", "JavaScript Escape Function"),
        (r"(?i)htmlspecialchars\(", "PHP htmlspecialchars Function"),
        (r"(?i)htmlentities\(", "PHP htmlentities Function"),
    ];

    for (pattern, description) in sanitization_patterns {
        if pattern.starts_with("(?i)") {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(body) {
                    info!(
                        "{}: Payload sanitized ({})",
                        "Sanitization Detected".yellow(),
                        description
                    );
                    return true;
                }
            }
        } else {
            if body.contains(pattern) {
                info!(
                    "{}: Payload sanitized ({})",
                    "Sanitization Detected".yellow(),
                    description
                );
                return true;
            }
        }
    }

    false
}

pub fn payload_contains_indicators(_payload: &str, body: &str) -> bool {
    let execution_patterns = vec!["alert(1)", "confirm(1)", "prompt(1)"];

    for pattern in execution_patterns {
        if body.contains(pattern) {
            return true;
        }
    }

    false
}

pub fn payload_present_in_dom(body: &str) -> bool {
    let document = Html::parse_document(body);
    let script_selector = Selector::parse("script").unwrap();
    let img_selector = Selector::parse("img").unwrap();
    let embed_selector = Selector::parse("embed").unwrap();

    for element in document.select(&script_selector) {
        if element.text().any(|text| text.contains("alert(1)")) {
            return true;
        }
    }

    for element in document.select(&img_selector) {
        if let Some(onerror) = element.value().attr("onerror") {
            if onerror.contains("alert(1)") {
                return true;
            }
        }
    }

    for element in document.select(&embed_selector) {
        if let Some(onerror) = element.value().attr("onerror") {
            if onerror.contains("alert(1)") {
                return true;
            }
        }
    }

    false
}

pub fn payload_inside_script_context(payload: &str, body: &str) -> bool {
    let script_context_patterns = vec![
        format!(r#""[^"]*{}[^"]*""#, regex::escape(payload)),
        format!(r#"'[^']*{}[^']*'"#, regex::escape(payload)),
        format!(r#"let\s+\w+\s*=\s*[^;]*{}[^;]*;"#, regex::escape(payload)),
        format!(r#"`[^`]*{}[^`]*`"#, regex::escape(payload)),
        format!(
            r#"function\s+\w+\s*\([^)]*\)\s*\{{[^}}]*{}\s*[^}}]*\}}"#,
            regex::escape(payload)
        ),
    ];

    for pattern in script_context_patterns {
        if let Ok(regex) = Regex::new(&pattern) {
            if regex.is_match(body) {
                info!(
                    "{}: Payload detected in script context",
                    "Script Context".yellow()
                );
                return true;
            }
        }
    }

    false
}
