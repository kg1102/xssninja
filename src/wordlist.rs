use reqwest::Error;

pub async fn fetch_wordlist(url: &str) -> Result<Vec<String>, Error> {
    let response = reqwest::get(url).await?;
    let text = response.text().await?;
    let parameters = text.lines().map(|line| line.trim().to_string()).collect();
    Ok(parameters)
}
