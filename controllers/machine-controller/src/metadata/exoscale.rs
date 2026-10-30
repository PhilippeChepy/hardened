//! Exoscale instance metadata (EC2-style, without IMDSv2 tokens).

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str;

use anyhow::Context as _;

use crate::hostnames;
use crate::metadata::Metadata;
use crate::metadata::http::Client;

const METADATA: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);

/// Fetches the instance's metadata from Exoscale's metadata service.
pub async fn fetch() -> anyhow::Result<Metadata> {
    fetch_from(&Client::new(METADATA)).await
}

async fn fetch_from(client: &Client) -> anyhow::Result<Metadata> {
    Ok(Metadata {
        instance_id: get_text(client, "/latest/meta-data/instance-id").await?,
        hostname: get_text(client, "/latest/meta-data/local-hostname")
            .await?
            .as_deref()
            .and_then(hostnames::sanitize),
        user_data: get_user_data(client, "/latest/user-data").await?,
    })
}

/// A metadata value as trimmed text; `None` when missing (404) or blank.
async fn get_text(client: &Client, path: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = client.get(path).await? else {
        return Ok(None);
    };
    let value = str::from_utf8(&value).with_context(|| format!("{path} is not valid UTF-8"))?;
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

/// User-data; `None` when missing or empty (metadata services may answer 200 with an empty body
/// rather than 404).
async fn get_user_data(client: &Client, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let value = client.get(path).await?;
    Ok(value.filter(|value| !value.is_empty()).map(Vec::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::http::mock;
    use crate::metadata::http::mock::Server;

    async fn metadata_server(user_data: &'static str) -> Server {
        Server::start(move |target| match target {
            "/latest/meta-data/instance-id" => mock::ok("5b0f6a0e-3f4c-4a3c-9d0e-1c2b3a4d5e6f"),
            "/latest/meta-data/local-hostname" => mock::ok("sks-pool-abc12"),
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
