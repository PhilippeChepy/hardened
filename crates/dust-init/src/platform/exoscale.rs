//! Exoscale instance metadata (EC2-style, without IMDSv2 tokens).
//!
//! Exoscale zones (e.g. `ch-gva-2`) are also its regions, so both fields carry the zone.

use http::Uri;

use super::Metadata;
use super::http::Client;

const METADATA: &str = "http://169.254.169.254";

pub async fn fetch() -> anyhow::Result<Metadata> {
    fetch_from(&Client::new(Uri::from_static(METADATA))?).await
}

async fn fetch_from(client: &Client) -> anyhow::Result<Metadata> {
    let text = |path| super::get_text(client, path, &[]);
    let zone = text("/latest/meta-data/availability-zone").await?;
    Ok(Metadata {
        instance_id: text("/latest/meta-data/instance-id").await?,
        hostname: text("/latest/meta-data/local-hostname")
            .await?
            .as_deref()
            .and_then(super::sanitize_hostname),
        region: zone.clone(),
        zone,
        user_data: super::get_user_data(client, "/latest/user-data", &[]).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::http::mock::{self, Server};
    use super::*;

    async fn metadata_server(user_data: &'static str) -> Server {
        Server::start(move |r| match r.target.as_str() {
            "/latest/meta-data/instance-id" => mock::ok("5b0f6a0e-3f4c-4a3c-9d0e-1c2b3a4d5e6f"),
            "/latest/meta-data/local-hostname" => mock::ok("sks-pool-abc12"),
            "/latest/meta-data/availability-zone" => mock::ok("ch-gva-2"),
            "/latest/user-data" => mock::ok(user_data),
            _ => mock::not_found(),
        })
        .await
    }

    #[tokio::test]
    async fn fetches_metadata() {
        let server = metadata_server("H4sIAAAA").await;
        let metadata = fetch_from(&server.client()).await.unwrap();
        assert_eq!(
            metadata,
            Metadata {
                instance_id: Some("5b0f6a0e-3f4c-4a3c-9d0e-1c2b3a4d5e6f".into()),
                hostname: Some("sks-pool-abc12".parse().unwrap()),
                region: Some("ch-gva-2".into()),
                zone: Some("ch-gva-2".into()),
                user_data: Some(b"H4sIAAAA".to_vec()),
            }
        );
    }

    #[tokio::test]
    async fn empty_user_data_is_none() {
        let server = metadata_server("").await;
        assert_eq!(fetch_from(&server.client()).await.unwrap().user_data, None);
    }
}
