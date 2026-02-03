//! ICE candidate types and handling.

use crate::error::{IceError, IceResult};
use crate::type_preference;
use std::net::SocketAddr;

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Host candidate (local interface address).
    Host,
    /// Server reflexive candidate (STUN-discovered public address).
    ServerReflexive,
    /// Peer reflexive candidate (discovered during connectivity checks).
    PeerReflexive,
    /// Relay candidate (TURN server allocated address).
    Relay,
}

impl CandidateType {
    /// Returns the type preference value per RFC 8445.
    pub fn type_preference(&self) -> u32 {
        match self {
            Self::Host => type_preference::HOST,
            Self::PeerReflexive => type_preference::PEER_REFLEXIVE,
            Self::ServerReflexive => type_preference::SERVER_REFLEXIVE,
            Self::Relay => type_preference::RELAY,
        }
    }

    /// Returns the SDP type string.
    pub fn as_sdp_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }

    /// Parses from SDP type string.
    pub fn from_sdp_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "srflx" => Some(Self::ServerReflexive),
            "prflx" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

impl std::fmt::Display for CandidateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_sdp_str())
    }
}

/// Transport protocol for candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// UDP transport.
    Udp,
    /// TCP transport (passive).
    TcpPassive,
    /// TCP transport (active).
    TcpActive,
    /// TCP transport (simultaneous open).
    TcpSo,
}

impl TransportProtocol {
    /// Returns the SDP transport string.
    pub fn as_sdp_str(&self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::TcpPassive => "TCP",
            Self::TcpActive => "TCP",
            Self::TcpSo => "TCP",
        }
    }
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_sdp_str())
    }
}

/// ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Foundation (unique per base + server + type combination).
    foundation: String,
    /// Component ID (1=RTP, 2=RTCP).
    component: u16,
    /// Transport protocol.
    transport: TransportProtocol,
    /// Priority (computed per RFC 8445).
    priority: u32,
    /// Transport address.
    address: SocketAddr,
    /// Candidate type.
    candidate_type: CandidateType,
    /// Related address (for srflx/prflx/relay).
    related_address: Option<SocketAddr>,
    /// Extension attributes.
    extensions: Vec<(String, String)>,
}

impl Candidate {
    /// Creates a new candidate.
    pub fn new(
        foundation: String,
        component: u16,
        transport: TransportProtocol,
        priority: u32,
        address: SocketAddr,
        candidate_type: CandidateType,
    ) -> Self {
        Self {
            foundation,
            component,
            transport,
            priority,
            address,
            candidate_type,
            related_address: None,
            extensions: Vec::new(),
        }
    }

    /// Creates a host candidate.
    pub fn host(address: SocketAddr, component: u16) -> Self {
        let foundation = Self::compute_foundation(CandidateType::Host, &address, None);
        let priority = Self::compute_priority(CandidateType::Host, component, 0);

        Self::new(
            foundation,
            component,
            TransportProtocol::Udp,
            priority,
            address,
            CandidateType::Host,
        )
    }

    /// Creates a server reflexive candidate.
    pub fn server_reflexive(
        address: SocketAddr,
        base_address: SocketAddr,
        component: u16,
    ) -> Self {
        let foundation =
            Self::compute_foundation(CandidateType::ServerReflexive, &base_address, None);
        let priority = Self::compute_priority(CandidateType::ServerReflexive, component, 0);

        let mut candidate = Self::new(
            foundation,
            component,
            TransportProtocol::Udp,
            priority,
            address,
            CandidateType::ServerReflexive,
        );
        candidate.related_address = Some(base_address);
        candidate
    }

    /// Creates a relay candidate.
    pub fn relay(
        address: SocketAddr,
        base_address: SocketAddr,
        component: u16,
    ) -> Self {
        let foundation = Self::compute_foundation(CandidateType::Relay, &base_address, None);
        let priority = Self::compute_priority(CandidateType::Relay, component, 0);

        let mut candidate = Self::new(
            foundation,
            component,
            TransportProtocol::Udp,
            priority,
            address,
            CandidateType::Relay,
        );
        candidate.related_address = Some(base_address);
        candidate
    }

    /// Returns the foundation.
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// Returns the component ID.
    pub fn component(&self) -> u16 {
        self.component
    }

    /// Returns the transport protocol.
    pub fn transport(&self) -> TransportProtocol {
        self.transport
    }

    /// Returns the priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Returns the transport address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the candidate type.
    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    /// Returns the related address if present.
    pub fn related_address(&self) -> Option<SocketAddr> {
        self.related_address
    }

    /// Sets the related address.
    pub fn set_related_address(&mut self, addr: SocketAddr) {
        self.related_address = Some(addr);
    }

    /// Adds an extension attribute.
    pub fn add_extension(&mut self, name: String, value: String) {
        self.extensions.push((name, value));
    }

    /// Returns extension attributes.
    pub fn extensions(&self) -> &[(String, String)] {
        &self.extensions
    }

    /// Returns the local preference value.
    ///
    /// The local preference is extracted from the priority field per RFC 8445 §5.1.2.1:
    /// priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)
    pub fn local_preference(&self) -> u32 {
        // Extract bits 8-23 from priority
        (self.priority >> 8) & 0xFFFF
    }

    /// Computes candidate foundation per RFC 8445 Section 5.1.1.3.
    ///
    /// Foundation is unique for each base/type/server combination.
    fn compute_foundation(
        candidate_type: CandidateType,
        base: &SocketAddr,
        _server: Option<&SocketAddr>,
    ) -> String {
        // Simple foundation: hash of type + base IP
        let type_byte = match candidate_type {
            CandidateType::Host => b'H',
            CandidateType::ServerReflexive => b'S',
            CandidateType::PeerReflexive => b'P',
            CandidateType::Relay => b'R',
        };

        let ip_bytes = match base.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        // Simple hash-like foundation
        let mut hash: u32 = type_byte as u32;
        for (i, byte) in ip_bytes.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add((*byte as u32) << (i % 4));
        }

        format!("{hash:08x}")
    }

    /// Computes candidate priority per RFC 8445 Section 5.1.2.1.
    ///
    /// priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)
    pub fn compute_priority(candidate_type: CandidateType, component: u16, local_pref: u32) -> u32 {
        let type_pref = candidate_type.type_preference();
        let local_pref = local_pref.min(65535); // 16 bits max

        (type_pref << 24) | ((local_pref as u32) << 8) | (256 - component as u32)
    }

    /// Formats as SDP candidate attribute.
    pub fn to_sdp(&self) -> String {
        let mut sdp = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport.as_sdp_str(),
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type.as_sdp_str()
        );

        if let Some(raddr) = self.related_address {
            sdp.push_str(&format!(" raddr {} rport {}", raddr.ip(), raddr.port()));
        }

        for (name, value) in &self.extensions {
            sdp.push_str(&format!(" {} {}", name, value));
        }

        sdp
    }

    /// Parses from SDP candidate attribute.
    pub fn from_sdp(sdp: &str) -> IceResult<Self> {
        let sdp = sdp.strip_prefix("candidate:").unwrap_or(sdp);
        let parts: Vec<&str> = sdp.split_whitespace().collect();

        if parts.len() < 8 {
            return Err(IceError::ParseError {
                reason: "not enough fields in candidate".to_string(),
            });
        }

        let foundation = parts[0].to_string();

        let component: u16 = parts[1].parse().map_err(|_| IceError::ParseError {
            reason: "invalid component".to_string(),
        })?;

        let transport = match parts[2].to_uppercase().as_str() {
            "UDP" => TransportProtocol::Udp,
            "TCP" => TransportProtocol::TcpPassive,
            _ => {
                return Err(IceError::ParseError {
                    reason: format!("unknown transport: {}", parts[2]),
                })
            }
        };

        let priority: u32 = parts[3].parse().map_err(|_| IceError::ParseError {
            reason: "invalid priority".to_string(),
        })?;

        let ip: std::net::IpAddr = parts[4].parse().map_err(|_| IceError::ParseError {
            reason: "invalid IP address".to_string(),
        })?;

        let port: u16 = parts[5].parse().map_err(|_| IceError::ParseError {
            reason: "invalid port".to_string(),
        })?;

        let address = SocketAddr::new(ip, port);

        // parts[6] should be "typ"
        if parts[6] != "typ" {
            return Err(IceError::ParseError {
                reason: "expected 'typ' keyword".to_string(),
            });
        }

        let candidate_type =
            CandidateType::from_sdp_str(parts[7]).ok_or_else(|| IceError::ParseError {
                reason: format!("unknown candidate type: {}", parts[7]),
            })?;

        let mut candidate = Candidate::new(
            foundation,
            component,
            transport,
            priority,
            address,
            candidate_type,
        );

        // Parse optional fields
        let mut i = 8;
        while i + 1 < parts.len() {
            match parts[i] {
                "raddr" => {
                    if i + 3 < parts.len() && parts[i + 2] == "rport" {
                        let rip: std::net::IpAddr =
                            parts[i + 1].parse().map_err(|_| IceError::ParseError {
                                reason: "invalid raddr".to_string(),
                            })?;
                        let rport: u16 =
                            parts[i + 3].parse().map_err(|_| IceError::ParseError {
                                reason: "invalid rport".to_string(),
                            })?;
                        candidate.related_address = Some(SocketAddr::new(rip, rport));
                        i += 4;
                    } else {
                        i += 2;
                    }
                }
                _ => {
                    // Extension attribute
                    candidate.add_extension(parts[i].to_string(), parts[i + 1].to_string());
                    i += 2;
                }
            }
        }

        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_candidate_type_preference() {
        assert!(CandidateType::Host.type_preference() > CandidateType::ServerReflexive.type_preference());
        assert!(CandidateType::ServerReflexive.type_preference() > CandidateType::Relay.type_preference());
    }

    #[test]
    fn test_candidate_type_sdp() {
        assert_eq!(CandidateType::Host.as_sdp_str(), "host");
        assert_eq!(CandidateType::ServerReflexive.as_sdp_str(), "srflx");
        assert_eq!(CandidateType::from_sdp_str("srflx"), Some(CandidateType::ServerReflexive));
    }

    #[test]
    fn test_host_candidate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let candidate = Candidate::host(addr, 1);

        assert_eq!(candidate.component(), 1);
        assert_eq!(candidate.address(), addr);
        assert_eq!(candidate.candidate_type(), CandidateType::Host);
        assert!(candidate.related_address().is_none());
    }

    #[test]
    fn test_server_reflexive_candidate() {
        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5060);
        let base_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let candidate = Candidate::server_reflexive(public_addr, base_addr, 1);

        assert_eq!(candidate.address(), public_addr);
        assert_eq!(candidate.related_address(), Some(base_addr));
        assert_eq!(candidate.candidate_type(), CandidateType::ServerReflexive);
    }

    #[test]
    fn test_priority_calculation() {
        // Host candidate should have higher priority than relay
        let host_priority = Candidate::compute_priority(CandidateType::Host, 1, 65535);
        let relay_priority = Candidate::compute_priority(CandidateType::Relay, 1, 65535);
        assert!(host_priority > relay_priority);

        // Component 1 (RTP) should have higher priority than component 2 (RTCP)
        let rtp_priority = Candidate::compute_priority(CandidateType::Host, 1, 0);
        let rtcp_priority = Candidate::compute_priority(CandidateType::Host, 2, 0);
        assert!(rtp_priority > rtcp_priority);
    }

    #[test]
    fn test_candidate_sdp_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let original = Candidate::host(addr, 1);

        let sdp = original.to_sdp();
        let parsed = Candidate::from_sdp(&sdp).unwrap();

        assert_eq!(parsed.component(), original.component());
        assert_eq!(parsed.address(), original.address());
        assert_eq!(parsed.candidate_type(), original.candidate_type());
        assert_eq!(parsed.priority(), original.priority());
    }

    #[test]
    fn test_candidate_sdp_with_related() {
        let public_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5060);
        let base_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5060);
        let original = Candidate::server_reflexive(public_addr, base_addr, 1);

        let sdp = original.to_sdp();
        assert!(sdp.contains("raddr"));
        assert!(sdp.contains("rport"));

        let parsed = Candidate::from_sdp(&sdp).unwrap();
        assert_eq!(parsed.related_address(), Some(base_addr));
    }

    #[test]
    fn test_sdp_parse_real_example() {
        let sdp = "candidate:1 1 UDP 2130706431 192.168.1.100 5060 typ host";
        let candidate = Candidate::from_sdp(sdp).unwrap();

        assert_eq!(candidate.foundation(), "1");
        assert_eq!(candidate.component(), 1);
        assert_eq!(candidate.candidate_type(), CandidateType::Host);
    }
}
