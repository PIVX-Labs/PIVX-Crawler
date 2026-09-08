use reqwest::Client;
use serde_json::json;
use std::error::Error;
use chrono::Utc;

pub struct Webhook {
    pub url: String,
}

impl Webhook {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn send_message(&self, message: &str) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        let payload = json!({
            "content": message
        });

        let res = client.post(&self.url)
            .json(&payload)
            .send()
            .await?;

        if res.status().is_success() {
            println!("Sent webhook: {}", message);
        } else {
            println!("Failed webhook: {:?}", res.text().await?);
        }

        Ok(())
    }

    pub async fn send_embed(&self, title: &str, description: &str, color: u32) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        let payload = json!({
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "timestamp": Utc::now().to_rfc3339()
            }]
        });

        let res = client.post(&self.url)
            .json(&payload)
            .send()
            .await?;

        if res.status().is_success() {
            println!("Sent webhook embed: {}", title);
        } else {
            println!("Failed to send webhook embed: {:?}", res.text().await?);
        }

        Ok(())
    }
}