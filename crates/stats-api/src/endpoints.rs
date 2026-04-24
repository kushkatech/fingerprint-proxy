#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsApiEndpoint {
    Stats {
        query: StatsQuery,
    },
    Fingerprints {
        kind: FingerprintKind,
        query: StatsQuery,
    },
    Health,
    ConfigVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintKind {
    Ja4t,
    Ja4,
    Ja4one,
}

impl FingerprintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ja4t => "ja4t",
            Self::Ja4 => "ja4",
            Self::Ja4one => "ja4one",
        }
    }

    fn parse(input: &str) -> Option<Self> {
        match input {
            "ja4t" => Some(Self::Ja4t),
            "ja4" => Some(Self::Ja4),
            "ja4one" => Some(Self::Ja4one),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsQuery {
    pub range: StatsRange,
}

impl Default for StatsQuery {
    fn default() -> Self {
        Self {
            range: StatsRange::DefaultWindow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsRange {
    DefaultWindow,
    ExplicitRange { from: u64, to: u64 },
    WindowSeconds(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointValidationError {
    pub kind: EndpointValidationErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointValidationErrorKind {
    NotFound,
    MethodNotAllowed,
    InvalidFingerprintKind,
    InvalidQuery,
}

pub fn validate_stats_api_endpoint(
    method: &str,
    uri: &str,
) -> Result<StatsApiEndpoint, EndpointValidationError> {
    let (path, query) = split_uri(uri);
    let route = classify_route(path)?;

    if method != "GET" {
        return Err(validation_error(
            EndpointValidationErrorKind::MethodNotAllowed,
            "only GET method is supported for statistics API endpoints",
        ));
    }

    match route {
        CandidateRoute::Stats => Ok(StatsApiEndpoint::Stats {
            query: parse_stats_query(query)?,
        }),
        CandidateRoute::Fingerprints { kind } => Ok(StatsApiEndpoint::Fingerprints {
            kind,
            query: parse_stats_query(query)?,
        }),
        CandidateRoute::Health => {
            reject_query_for_metadata_endpoint(query)?;
            Ok(StatsApiEndpoint::Health)
        }
        CandidateRoute::ConfigVersion => {
            reject_query_for_metadata_endpoint(query)?;
            Ok(StatsApiEndpoint::ConfigVersion)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateRoute {
    Stats,
    Fingerprints { kind: FingerprintKind },
    Health,
    ConfigVersion,
}

fn classify_route(path: &str) -> Result<CandidateRoute, EndpointValidationError> {
    if path == "/stats" {
        return Ok(CandidateRoute::Stats);
    }
    if path == "/stats/health" {
        return Ok(CandidateRoute::Health);
    }
    if path == "/stats/config-version" {
        return Ok(CandidateRoute::ConfigVersion);
    }
    if path == "/stats/fingerprints" || path == "/stats/fingerprints/" {
        return Err(validation_error(
            EndpointValidationErrorKind::InvalidFingerprintKind,
            "fingerprint kind must be one of: ja4t, ja4, ja4one",
        ));
    }
    if let Some(kind_raw) = path.strip_prefix("/stats/fingerprints/") {
        if kind_raw.is_empty() || kind_raw.contains('/') {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidFingerprintKind,
                "fingerprint kind must be one of: ja4t, ja4, ja4one",
            ));
        }
        let Some(kind) = FingerprintKind::parse(kind_raw) else {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidFingerprintKind,
                "fingerprint kind must be one of: ja4t, ja4, ja4one",
            ));
        };
        return Ok(CandidateRoute::Fingerprints { kind });
    }

    Err(validation_error(
        EndpointValidationErrorKind::NotFound,
        "statistics API endpoint not found",
    ))
}

fn split_uri(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (uri, None),
    }
}

fn reject_query_for_metadata_endpoint(query: Option<&str>) -> Result<(), EndpointValidationError> {
    if query.is_some_and(|q| !q.is_empty()) {
        return Err(validation_error(
            EndpointValidationErrorKind::InvalidQuery,
            "query parameters are not supported for this endpoint",
        ));
    }
    Ok(())
}

fn parse_stats_query(query: Option<&str>) -> Result<StatsQuery, EndpointValidationError> {
    let Some(query) = query else {
        return Ok(StatsQuery::default());
    };
    if query.is_empty() {
        return Ok(StatsQuery::default());
    }

    let mut from: Option<u64> = None;
    let mut to: Option<u64> = None;
    let mut window_seconds: Option<u64> = None;

    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidQuery,
                "query string contains an empty parameter",
            ));
        }
        let Some((key, value)) = pair.split_once('=') else {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidQuery,
                "query parameter must use key=value format",
            ));
        };
        if key.is_empty() || value.is_empty() {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidQuery,
                "query parameter key and value must be non-empty",
            ));
        }
        match key {
            "from" => parse_once_u64("from", value, &mut from)?,
            "to" => parse_once_u64("to", value, &mut to)?,
            "window_seconds" => parse_once_u64("window_seconds", value, &mut window_seconds)?,
            _ => {
                return Err(validation_error(
                    EndpointValidationErrorKind::InvalidQuery,
                    "unsupported query parameter for statistics endpoint",
                ));
            }
        }
    }

    let range = match (from, to, window_seconds) {
        (None, None, None) => StatsRange::DefaultWindow,
        (Some(from), Some(to), None) => {
            if from > to {
                return Err(validation_error(
                    EndpointValidationErrorKind::InvalidQuery,
                    "`from` must be less than or equal to `to`",
                ));
            }
            StatsRange::ExplicitRange { from, to }
        }
        (None, None, Some(window)) => {
            if window == 0 {
                return Err(validation_error(
                    EndpointValidationErrorKind::InvalidQuery,
                    "`window_seconds` must be greater than zero",
                ));
            }
            StatsRange::WindowSeconds(window)
        }
        _ => {
            return Err(validation_error(
                EndpointValidationErrorKind::InvalidQuery,
                "invalid query parameter combination for statistics endpoint",
            ));
        }
    };

    Ok(StatsQuery { range })
}

fn parse_once_u64(
    key: &str,
    value: &str,
    slot: &mut Option<u64>,
) -> Result<(), EndpointValidationError> {
    if slot.is_some() {
        return Err(validation_error(
            EndpointValidationErrorKind::InvalidQuery,
            "duplicate query parameter is not allowed",
        ));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(validation_error(
            EndpointValidationErrorKind::InvalidQuery,
            "query parameter value must be an unsigned integer",
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        validation_error(
            EndpointValidationErrorKind::InvalidQuery,
            "query parameter value is out of range",
        )
    })?;
    *slot = Some(parsed);
    let _ = key;
    Ok(())
}

fn validation_error(kind: EndpointValidationErrorKind, message: &str) -> EndpointValidationError {
    EndpointValidationError {
        kind,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_stats_endpoint_with_default_window() {
        let endpoint = validate_stats_api_endpoint("GET", "/stats").expect("endpoint");
        assert_eq!(
            endpoint,
            StatsApiEndpoint::Stats {
                query: StatsQuery {
                    range: StatsRange::DefaultWindow
                }
            }
        );
    }

    #[test]
    fn accepts_stats_endpoint_with_explicit_range() {
        let endpoint =
            validate_stats_api_endpoint("GET", "/stats?from=10&to=20").expect("endpoint");
        assert_eq!(
            endpoint,
            StatsApiEndpoint::Stats {
                query: StatsQuery {
                    range: StatsRange::ExplicitRange { from: 10, to: 20 }
                }
            }
        );
    }

    #[test]
    fn accepts_stats_endpoint_with_window_seconds() {
        let endpoint =
            validate_stats_api_endpoint("GET", "/stats?window_seconds=60").expect("endpoint");
        assert_eq!(
            endpoint,
            StatsApiEndpoint::Stats {
                query: StatsQuery {
                    range: StatsRange::WindowSeconds(60)
                }
            }
        );
    }

    #[test]
    fn accepts_fingerprint_kind_endpoint() {
        let endpoint = validate_stats_api_endpoint("GET", "/stats/fingerprints/ja4one")
            .expect("fingerprint endpoint");
        assert_eq!(
            endpoint,
            StatsApiEndpoint::Fingerprints {
                kind: FingerprintKind::Ja4one,
                query: StatsQuery {
                    range: StatsRange::DefaultWindow
                }
            }
        );
    }

    #[test]
    fn accepts_health_and_config_version_without_query() {
        assert_eq!(
            validate_stats_api_endpoint("GET", "/stats/health").expect("health"),
            StatsApiEndpoint::Health
        );
        assert_eq!(
            validate_stats_api_endpoint("GET", "/stats/config-version").expect("config-version"),
            StatsApiEndpoint::ConfigVersion
        );
    }

    #[test]
    fn rejects_unknown_path_with_not_found() {
        let err = validate_stats_api_endpoint("GET", "/stats/unknown").expect_err("must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::NotFound);
    }

    #[test]
    fn rejects_non_get_method_for_supported_path() {
        let err = validate_stats_api_endpoint("POST", "/stats").expect_err("must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::MethodNotAllowed);
    }

    #[test]
    fn rejects_invalid_fingerprint_kind() {
        let err =
            validate_stats_api_endpoint("GET", "/stats/fingerprints/ja3").expect_err("must fail");
        assert_eq!(
            err.kind,
            EndpointValidationErrorKind::InvalidFingerprintKind
        );
    }

    #[test]
    fn rejects_invalid_query_combinations() {
        let err = validate_stats_api_endpoint("GET", "/stats?from=10")
            .expect_err("from without to must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);

        let err = validate_stats_api_endpoint("GET", "/stats?window_seconds=60&from=10&to=20")
            .expect_err("window with from/to must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);

        let err = validate_stats_api_endpoint("GET", "/stats?from=20&to=10")
            .expect_err("from after to must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);
    }

    #[test]
    fn rejects_invalid_query_values_and_duplicates() {
        let err = validate_stats_api_endpoint("GET", "/stats?window_seconds=0")
            .expect_err("zero window must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);

        let err = validate_stats_api_endpoint("GET", "/stats?from=abc&to=10")
            .expect_err("non-numeric must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);

        let err = validate_stats_api_endpoint("GET", "/stats?from=1&from=2&to=3")
            .expect_err("duplicate key must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);
    }

    #[test]
    fn rejects_query_for_metadata_endpoints() {
        let err = validate_stats_api_endpoint("GET", "/stats/health?window_seconds=60")
            .expect_err("query on health must fail");
        assert_eq!(err.kind, EndpointValidationErrorKind::InvalidQuery);
    }
}
