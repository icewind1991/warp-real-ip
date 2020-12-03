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
    warp::header::<String>("x-forwarded-for")
        .map(|forwarded: String| {
            forwarded
                .split(',')
                .map(str::trim)
                .map(IpAddr::from_str)
                .filter_map(Result::ok)
                .collect::<Vec<IpAddr>>()
        })
        .or(warp::header("x-real-ip").map(|ip| vec![ip]))
        .unify()
        .or(warp::any().map(|| vec![]))
        .unify()
}
