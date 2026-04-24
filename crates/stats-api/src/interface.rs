use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsApiRequestContext<'a> {
    pub peer_ip: IpAddr,
    pub bearer_token: Option<&'a str>,
}
