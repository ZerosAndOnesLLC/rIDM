//! Where a request comes from, for the risk policy's location signals.
//!
//! Two sources, in order:
//!
//! 1. **Headers a trusted proxy or CDN sets** (`CloudFront-Viewer-Country`,
//!    `CF-IPCountry`, ...). They are only believed when the request reached
//!    us through a [`Config::trusted_proxies`](crate::config::Config) peer —
//!    exactly the rule `X-Forwarded-For` follows — because a client can put
//!    any country it likes in a header of its own.
//! 2. **A MaxMind DB file** the deployment supplies (`GEOIP_DB`), read into
//!    memory at startup. A City database also yields coordinates; a Country
//!    database yields the country alone.
//!
//! A deployment that configures neither resolves nothing, and a signal that
//! cannot be computed is never raised: adaptive authentication degrades to
//! the device and velocity signals rather than failing sign-ins.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use axum::http::HeaderMap;

use crate::config::GeoIpConfig;
use crate::state::AppState;

/// Where a request appears to come from. A country with no coordinates is
/// normal (a country-only source); coordinates without a country are not
/// kept, since the country is what history is keyed by.
#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

impl Location {
    pub fn coordinates(&self) -> Option<(f64, f64)> {
        Some((self.latitude?, self.longitude?))
    }
}

/// Great-circle distance in kilometres.
pub fn distance_km(from: (f64, f64), to: (f64, f64)) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (lat1, lon1) = (from.0.to_radians(), from.1.to_radians());
    let (lat2, lon2) = (to.0.to_radians(), to.1.to_radians());
    let (dlat, dlon) = (lat2 - lat1, lon2 - lon1);
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().clamp(0.0, 1.0).asin()
}

/// The MaxMind database, if one was configured and could be read. Held in
/// [`AppState`] so the file is parsed once.
#[derive(Clone, Default)]
pub struct GeoDatabase(Option<Arc<maxminddb::Reader<Vec<u8>>>>);

impl std::fmt::Debug for GeoDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GeoDatabase")
            .field(&self.0.is_some())
            .finish()
    }
}

impl GeoDatabase {
    /// Read the file at `path`. A database that cannot be read is logged and
    /// treated as absent: a corrupt or missing file must not stop the server
    /// from signing users in.
    pub fn open(path: &Path) -> Self {
        match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| {
                maxminddb::Reader::from_source(b)
                    .map(Arc::new)
                    .map_err(|e| e.to_string())
            }) {
            Ok(reader) => {
                tracing::info!(
                    path = %path.display(),
                    kind = %reader.metadata().database_type,
                    "geoip database loaded"
                );
                Self(Some(reader))
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "geoip database unusable; location signals are off");
                Self::default()
            }
        }
    }

    pub fn from_config(config: &GeoIpConfig) -> Self {
        match &config.db_path {
            Some(path) => Self::open(path),
            None => Self::default(),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.0.is_some()
    }

    /// Look `ip` up. Private and otherwise unlistable addresses simply have
    /// no answer.
    pub fn lookup(&self, ip: IpAddr) -> Option<Location> {
        let reader = self.0.as_ref()?;
        // A Country database decodes into the same shape with the city and
        // location fields left empty, so one lookup serves both.
        let city = reader
            .lookup(ip)
            .ok()?
            .decode::<maxminddb::geoip2::City>()
            .ok()??;
        let country = city.country.iso_code.or(city.registered_country.iso_code)?;
        normalize(country, city.location.latitude, city.location.longitude)
    }
}

/// The country (and point) a trusted proxy reported, if any.
fn from_headers(config: &GeoIpConfig, headers: &HeaderMap) -> Option<Location> {
    let first = |names: &[String]| -> Option<String> {
        names
            .iter()
            .find_map(|n| headers.get(n.as_str()))
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let country = first(&config.country_headers)?;
    let coordinate = |names: &[String]| first(names).and_then(|v| v.parse::<f64>().ok());
    normalize(
        &country,
        coordinate(&config.latitude_headers),
        coordinate(&config.longitude_headers),
    )
}

/// An ISO 3166-1 alpha-2 country and, when both are present and in range,
/// its coordinates. `XX` and `T1` (Cloudflare's "unknown" and "Tor") say
/// nothing about where the user is, so they resolve to nothing at all.
fn normalize(country: &str, latitude: Option<f64>, longitude: Option<f64>) -> Option<Location> {
    let country = country.trim().to_ascii_uppercase();
    if country.len() != 2
        || !country.bytes().all(|b| b.is_ascii_uppercase())
        || matches!(country.as_str(), "XX" | "T1")
    {
        return None;
    }
    let point = match (latitude, longitude) {
        (Some(lat), Some(lon))
            if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) =>
        {
            (Some(lat), Some(lon))
        }
        _ => (None, None),
    };
    Some(Location {
        country,
        latitude: point.0,
        longitude: point.1,
    })
}

/// Did this request arrive through one of the deployment's own proxies?
fn via_trusted_proxy(state: &AppState, peer: Option<SocketAddr>) -> bool {
    peer.is_some_and(|p| {
        state
            .config
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&p.ip()))
    })
}

/// The address a request came from and where that address is: the two facts
/// every sign-in path hands to the risk policy. Resolved at the edge, where
/// the peer is still known, because that is what decides whether a proxy's
/// geo headers may be believed.
#[derive(Debug, Clone, Default)]
pub struct Origin {
    pub ip: Option<IpAddr>,
    pub location: Option<Location>,
}

impl Origin {
    pub fn of_request(state: &AppState, headers: &HeaderMap, peer: Option<SocketAddr>) -> Self {
        let ip = crate::middleware::client_ip_addr(state, headers, peer);
        Self {
            ip,
            location: locate(state, headers, peer, ip),
        }
    }

    pub fn ip_string(&self) -> Option<String> {
        self.ip.map(|i| i.to_string())
    }
}

/// Locate a request: the proxy's headers when they can be trusted, otherwise
/// the database, otherwise nothing.
pub fn locate(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    ip: Option<IpAddr>,
) -> Option<Location> {
    if via_trusted_proxy(state, peer)
        && let Some(loc) = from_headers(&state.config.geoip, headers)
    {
        return Some(loc);
    }
    state.geoip.lookup(ip?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_between_known_points() {
        // London to Paris: ~344 km.
        let km = distance_km((51.5074, -0.1278), (48.8566, 2.3522));
        assert!((340.0..350.0).contains(&km), "{km}");
        // The same point is no distance at all.
        assert_eq!(distance_km((10.0, 10.0), (10.0, 10.0)), 0.0);
        // London to Sydney, the far side of the world: ~16_990 km.
        let km = distance_km((51.5074, -0.1278), (-33.8688, 151.2093));
        assert!((16_900.0..17_100.0).contains(&km), "{km}");
    }

    #[test]
    fn normalizes_countries_and_drops_useless_ones() {
        let loc = normalize("gb", Some(51.5), Some(-0.12)).expect("gb");
        assert_eq!(loc.country, "GB");
        assert_eq!(loc.coordinates(), Some((51.5, -0.12)));
        // A country with only one coordinate keeps the country.
        let loc = normalize("US", Some(40.0), None).expect("us");
        assert_eq!(loc.coordinates(), None);
        // Out of range is no better than missing.
        assert_eq!(
            normalize("US", Some(91.0), Some(0.0)).expect("us").latitude,
            None
        );
        // Neither an unknown country nor a malformed one says anything.
        assert!(normalize("XX", None, None).is_none());
        assert!(normalize("T1", None, None).is_none());
        assert!(normalize("GBR", None, None).is_none());
        assert!(normalize("", None, None).is_none());
    }

    #[test]
    fn reads_the_first_header_present() {
        let config = GeoIpConfig::default();
        let mut headers = HeaderMap::new();
        assert!(from_headers(&config, &headers).is_none());
        headers.insert("cf-ipcountry", "de".parse().unwrap());
        let loc = from_headers(&config, &headers).expect("cf country");
        assert_eq!(loc.country, "DE");
        assert_eq!(loc.coordinates(), None);
        // CloudFront is listed first, so it wins, and it brings a point.
        headers.insert("cloudfront-viewer-country", "FR".parse().unwrap());
        headers.insert("cloudfront-viewer-latitude", "48.85".parse().unwrap());
        headers.insert("cloudfront-viewer-longitude", "2.35".parse().unwrap());
        let loc = from_headers(&config, &headers).expect("cloudfront country");
        assert_eq!(loc.country, "FR");
        assert_eq!(loc.coordinates(), Some((48.85, 2.35)));
    }

    #[test]
    fn a_database_that_is_not_there_is_simply_absent() {
        let db = GeoDatabase::open(Path::new("/nonexistent/GeoLite2-City.mmdb"));
        assert!(!db.is_loaded());
        assert_eq!(db.lookup("203.0.113.7".parse().unwrap()), None);
    }
}
