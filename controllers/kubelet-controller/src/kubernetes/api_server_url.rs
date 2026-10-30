//! The URL of the cluster's API server.

use controllers_helpers::validated_string;
use http::Uri;

validated_string!(
    /// The API server's URL: `https://<host>[:<port>]`, with no path.
    ApiServerUrl,
    "API server URL",
    check_api_server_url
);

fn check_api_server_url(url: &str) -> Result<(), &'static str> {
    let uri: Uri = url.parse().map_err(|_| "is not a URL")?;
    let authority = uri.authority().ok_or("must name a host")?;
    if uri.scheme_str() != Some("https") {
        Err("must be https")
    } else if authority.as_str().contains('@') {
        Err("must not hold credentials")
    } else if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        Err("must have no path or query")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_server_urls() {
        for good in [
            "https://k8s.example.com",
            "https://192.0.2.1:6443",
            "https://[2001:db8::1]:6443/",
        ] {
            assert!(good.parse::<ApiServerUrl>().is_ok(), "{good}");
        }
        for bad in [
            "http://k8s.example.com",
            "k8s.example.com:6443",
            "https://user:pw@k8s.example.com",
            "https://k8s.example.com/api",
            "https://k8s.example.com?x=1",
            "https://k8s example.com",
        ] {
            assert!(bad.parse::<ApiServerUrl>().is_err(), "{bad}");
        }
    }
}
