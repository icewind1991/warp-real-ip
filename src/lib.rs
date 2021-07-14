use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rfc7239::{parse, Forwarded, NodeIdentifier, NodeName};
use std::convert::Infallible;
use std::iter::{once, FromIterator, IntoIterator};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use warp::filters::addr::remote;
use warp::Filter;

/// Represents a set of IP networks.
#[derive(Debug, Clone)]
pub struct IpNetworks {
    networks: Vec<IpNetwork>,
}

impl IpNetworks {
    /// Checks if addr is part of any IP networks included.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.networks.iter().any(|&network| network.contains(*addr))
    }

    /// Special constructor that builds IpNetwork from an iterator of IP addresses.
    pub fn from_ipaddr_iter<'a, T: Iterator<Item = &'a IpAddr>>(addrs: T) -> Self {
        Self::from_iter(addrs.map(|&addr| -> IpNetwork {
            match addr {
                IpAddr::V4(addr) => Ipv4Network::from(addr).into(),
                IpAddr::V6(addr) => Ipv6Network::from(addr).into(),
            }
        }))
    }
}

impl From<&Vec<IpAddr>> for IpNetworks {
    fn from(addrs: &Vec<IpAddr>) -> Self {
        Self::from_ipaddr_iter(addrs.iter())
    }
}

impl FromIterator<IpNetwork> for IpNetworks {
    fn from_iter<T: IntoIterator<Item = IpNetwork>>(addrs: T) -> Self {
        IpNetworks {
            networks: Vec::<IpNetwork>::from_iter(addrs),
        }
    }
}

/// Creates a `Filter` that provides the "real ip" of the connected client.
///
/// This uses the "x-forwarded-for" or "x-real-ip" headers set by reverse proxies.
/// To stop clients from abusing these headers, only headers set by trusted remotes will be accepted.
///
/// Note that if multiple forwarded-for addresses are present, wich can be the case when using nested reverse proxies,
/// all proxies in the chain have to be within the list of trusted proxies.
///
/// ## Example
///
/// ```no_run
/// use warp::Filter;
/// use warp_real_ip::real_ip;
/// use std::net::IpAddr;
///
/// let proxy_addr = [127, 10, 0, 1].into();
/// warp::any()
///     .and(real_ip(vec![proxy_addr]))
///     .map(|addr: Option<IpAddr>| format!("Hello {}", addr.unwrap()));
/// ```
pub fn real_ip(
    trusted_proxies: IpNetworks,
) -> impl Filter<Extract = (Option<IpAddr>,), Error = Infallible> + Clone {
    remote().and(get_forwarded_for()).map(
        move |addr: Option<SocketAddr>, forwarded_for: Vec<IpAddr>| {
            addr.map(|addr| {
                let hops = forwarded_for.iter().copied().chain(once(addr.ip()));
                for hop in hops.rev() {
                    if !trusted_proxies.contains(&hop) {
                        return hop;
                    }
                }

                // all hops were trusted, return the last one
                forwarded_for.first().copied().unwrap_or(addr.ip())
            })
        },
    )
}

/// Creates a `Filter` that extracts the ip addresses from the the "forwarded for" chain
pub fn get_forwarded_for() -> impl Filter<Extract = (Vec<IpAddr>,), Error = Infallible> + Clone {
    warp::header("x-forwarded-for")
        .map(|list: CommaSeparated<IpAddr>| list.into_inner())
        .or(warp::header("x-real-ip").map(|ip| vec![ip]))
        .unify()
        .or(warp::header("forwarded").map(|header: String| {
            parse(&header)
                .filter_map(|forward| match forward {
                    Ok(Forwarded {
                        forwarded_for:
                            Some(NodeIdentifier {
                                name: NodeName::Ip(ip),
                                ..
                            }),
                        ..
                    }) => Some(ip),
                    _ => None,
                })
                .collect::<Vec<_>>()
        }))
        .unify()
        .or(warp::any().map(|| vec![]))
        .unify()
}

/// Newtype so we can implement FromStr
struct CommaSeparated<T>(Vec<T>);

impl<T> CommaSeparated<T> {
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: FromStr> FromStr for CommaSeparated<T> {
    type Err = T::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = s
            .split(',')
            .map(str::trim)
            .map(T::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CommaSeparated(vec))
    }
}
