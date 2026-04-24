use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4CidrParseError {
    MissingSeparator,
    InvalidAddress,
    InvalidPrefixLength,
    PrefixLengthOutOfRange(u8),
}

impl Ipv4Cidr {
    pub fn parse(input: &str) -> Result<Self, Ipv4CidrParseError> {
        input.parse()
    }

    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, Ipv4CidrParseError> {
        if prefix_len > 32 {
            return Err(Ipv4CidrParseError::PrefixLengthOutOfRange(prefix_len));
        }

        let mask = prefix_mask(prefix_len);
        let normalized = Ipv4Addr::from(u32::from(network) & mask);

        Ok(Self {
            network: normalized,
            prefix_len,
        })
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = prefix_mask(self.prefix_len);
        (u32::from(self.network) & mask) == (u32::from(address) & mask)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = Ipv4CidrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (address_part, prefix_part) = input
            .split_once('/')
            .ok_or(Ipv4CidrParseError::MissingSeparator)?;

        let network = address_part
            .parse::<Ipv4Addr>()
            .map_err(|_| Ipv4CidrParseError::InvalidAddress)?;
        let prefix_len = prefix_part
            .parse::<u8>()
            .map_err(|_| Ipv4CidrParseError::InvalidPrefixLength)?;

        Self::new(network, prefix_len)
    }
}

pub fn ipv4_matches_cidr(address: Ipv4Addr, cidr: &str) -> Result<bool, Ipv4CidrParseError> {
    Ok(Ipv4Cidr::parse(cidr)?.contains(address))
}

fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_member_ipv4_address() {
        let cidr = Ipv4Cidr::parse("192.0.2.0/24").expect("cidr");
        assert!(cidr.contains(Ipv4Addr::new(192, 0, 2, 42)));
    }

    #[test]
    fn rejects_non_member_ipv4_address() {
        let cidr = Ipv4Cidr::parse("192.0.2.0/24").expect("cidr");
        assert!(!cidr.contains(Ipv4Addr::new(198, 51, 100, 1)));
    }

    #[test]
    fn supports_prefix_zero_for_full_ipv4_space() {
        let cidr = Ipv4Cidr::parse("0.0.0.0/0").expect("cidr");
        assert!(cidr.contains(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(cidr.contains(Ipv4Addr::new(203, 0, 113, 99)));
    }

    #[test]
    fn supports_prefix_thirty_two_for_exact_host() {
        let cidr = Ipv4Cidr::parse("203.0.113.9/32").expect("cidr");
        assert!(cidr.contains(Ipv4Addr::new(203, 0, 113, 9)));
        assert!(!cidr.contains(Ipv4Addr::new(203, 0, 113, 10)));
    }

    #[test]
    fn normalizes_network_bits_on_parse() {
        let cidr = Ipv4Cidr::parse("192.0.2.99/24").expect("cidr");
        assert_eq!(cidr.network(), Ipv4Addr::new(192, 0, 2, 0));
        assert!(cidr.contains(Ipv4Addr::new(192, 0, 2, 15)));
    }

    #[test]
    fn one_shot_matching_api_works() {
        assert!(ipv4_matches_cidr(Ipv4Addr::new(192, 0, 2, 10), "192.0.2.0/24").expect("parse"));
        assert!(
            !ipv4_matches_cidr(Ipv4Addr::new(198, 51, 100, 10), "192.0.2.0/24").expect("parse")
        );
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = Ipv4Cidr::parse("192.0.2.0").expect_err("must fail");
        assert_eq!(err, Ipv4CidrParseError::MissingSeparator);
    }

    #[test]
    fn parse_rejects_invalid_address() {
        let err = Ipv4Cidr::parse("999.0.2.0/24").expect_err("must fail");
        assert_eq!(err, Ipv4CidrParseError::InvalidAddress);
    }

    #[test]
    fn parse_rejects_invalid_prefix_number() {
        let err = Ipv4Cidr::parse("192.0.2.0/not-a-number").expect_err("must fail");
        assert_eq!(err, Ipv4CidrParseError::InvalidPrefixLength);
    }

    #[test]
    fn parse_rejects_prefix_over_32() {
        let err = Ipv4Cidr::parse("192.0.2.0/33").expect_err("must fail");
        assert_eq!(err, Ipv4CidrParseError::PrefixLengthOutOfRange(33));
    }

    #[test]
    fn parse_rejects_ipv6_address_in_ipv4_cidr() {
        let err = Ipv4Cidr::parse("2001:db8::/64").expect_err("must fail");
        assert_eq!(err, Ipv4CidrParseError::InvalidAddress);
    }
}
