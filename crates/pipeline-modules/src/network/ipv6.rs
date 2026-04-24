use fingerprint_proxy_core::ipv6_mapped::normalize_ipv6_mapped_ip;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6CidrParseError {
    MissingSeparator,
    InvalidAddress,
    InvalidPrefixLength,
    PrefixLengthOutOfRange(u8),
}

impl Ipv6Cidr {
    pub fn parse(input: &str) -> Result<Self, Ipv6CidrParseError> {
        input.parse()
    }

    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Result<Self, Ipv6CidrParseError> {
        if prefix_len > 128 {
            return Err(Ipv6CidrParseError::PrefixLengthOutOfRange(prefix_len));
        }

        let mask = prefix_mask(prefix_len);
        let normalized = Ipv6Addr::from(u128::from(network) & mask);

        Ok(Self {
            network: normalized,
            prefix_len,
        })
    }

    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, address: Ipv6Addr) -> bool {
        let mask = prefix_mask(self.prefix_len);
        (u128::from(self.network) & mask) == (u128::from(address) & mask)
    }
}

impl FromStr for Ipv6Cidr {
    type Err = Ipv6CidrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (address_part, prefix_part) = input
            .split_once('/')
            .ok_or(Ipv6CidrParseError::MissingSeparator)?;

        let network = address_part
            .parse::<Ipv6Addr>()
            .map_err(|_| Ipv6CidrParseError::InvalidAddress)?;
        let prefix_len = prefix_part
            .parse::<u8>()
            .map_err(|_| Ipv6CidrParseError::InvalidPrefixLength)?;

        Self::new(network, prefix_len)
    }
}

pub fn ipv6_matches_cidr(address: Ipv6Addr, cidr: &str) -> Result<bool, Ipv6CidrParseError> {
    Ok(Ipv6Cidr::parse(cidr)?.contains(address))
}

pub fn normalize_client_network_ip(addr: IpAddr) -> IpAddr {
    normalize_ipv6_mapped_ip(addr)
}

fn prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_member_ipv6_address() {
        let cidr = Ipv6Cidr::parse("2001:db8::/32").expect("cidr");
        assert!(cidr.contains("2001:db8:0:1::1".parse::<Ipv6Addr>().expect("valid ipv6")));
    }

    #[test]
    fn rejects_non_member_ipv6_address() {
        let cidr = Ipv6Cidr::parse("2001:db8::/32").expect("cidr");
        assert!(!cidr.contains("2001:db9::1".parse::<Ipv6Addr>().expect("valid ipv6")));
    }

    #[test]
    fn supports_prefix_zero_for_full_ipv6_space() {
        let cidr = Ipv6Cidr::parse("::/0").expect("cidr");
        assert!(cidr.contains("2001:db8::1".parse::<Ipv6Addr>().expect("valid")));
        assert!(cidr.contains("fd00::1".parse::<Ipv6Addr>().expect("valid")));
    }

    #[test]
    fn supports_prefix_one_hundred_twenty_eight_for_exact_host() {
        let cidr = Ipv6Cidr::parse("2001:db8::1/128").expect("cidr");
        assert!(cidr.contains("2001:db8::1".parse::<Ipv6Addr>().expect("valid")));
        assert!(!cidr.contains("2001:db8::2".parse::<Ipv6Addr>().expect("valid")));
    }

    #[test]
    fn normalizes_network_bits_on_parse() {
        let cidr = Ipv6Cidr::parse("2001:db8::1234/64").expect("cidr");
        assert_eq!(
            cidr.network(),
            "2001:db8::".parse::<Ipv6Addr>().expect("valid ipv6")
        );
        assert!(cidr.contains("2001:db8::beef".parse::<Ipv6Addr>().expect("valid")));
    }

    #[test]
    fn one_shot_matching_api_works() {
        assert!(ipv6_matches_cidr(
            "2001:db8::10".parse::<Ipv6Addr>().expect("valid"),
            "2001:db8::/32"
        )
        .expect("parse"));
        assert!(!ipv6_matches_cidr(
            "2001:db9::10".parse::<Ipv6Addr>().expect("valid"),
            "2001:db8::/32"
        )
        .expect("parse"));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = Ipv6Cidr::parse("2001:db8::").expect_err("must fail");
        assert_eq!(err, Ipv6CidrParseError::MissingSeparator);
    }

    #[test]
    fn parse_rejects_invalid_address() {
        let err = Ipv6Cidr::parse("not-an-ipv6/32").expect_err("must fail");
        assert_eq!(err, Ipv6CidrParseError::InvalidAddress);
    }

    #[test]
    fn parse_rejects_invalid_prefix_number() {
        let err = Ipv6Cidr::parse("2001:db8::/not-a-number").expect_err("must fail");
        assert_eq!(err, Ipv6CidrParseError::InvalidPrefixLength);
    }

    #[test]
    fn parse_rejects_prefix_over_128() {
        let err = Ipv6Cidr::parse("2001:db8::/129").expect_err("must fail");
        assert_eq!(err, Ipv6CidrParseError::PrefixLengthOutOfRange(129));
    }

    #[test]
    fn parse_rejects_ipv4_address_in_ipv6_cidr() {
        let err = Ipv6Cidr::parse("192.0.2.0/24").expect_err("must fail");
        assert_eq!(err, Ipv6CidrParseError::InvalidAddress);
    }

    #[test]
    fn normalizes_ipv6_mapped_ipv4_for_network_classification() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
        assert_eq!(
            normalize_client_network_ip(mapped),
            IpAddr::V4("192.0.2.10".parse().expect("ipv4"))
        );
        assert_eq!(
            normalize_client_network_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }
}
