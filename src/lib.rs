use std::convert::Infallible;
use std::iter::once;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use warp::filters::addr::remote;
use warp::Filter;

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
    trusted_proxies: Vec<IpAddr>,
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
        .map(|list: IpList| list.0)
        .or(warp::header("x-real-ip").map(|ip| vec![ip]))
        .unify()
        .or(warp::any().map(|| vec![]))
        .unify()
}

/// Newtype so we can implement FromStr
struct IpList(Vec<IpAddr>);

impl FromStr for IpList {
    type Err = <IpAddr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = s
            .split(',')
            .map(str::trim)
            .map(IpAddr::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(IpList(vec))
    }
}
