use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use warp::filters::addr::remote;
use warp::Filter;

/// Creates a `Filter` that provides the "real ip" of the connected client.
pub fn real_ip<'a>(
    trusted_proxies: &'a [IpAddr],
) -> impl Filter<Extract = (Option<IpAddr>,), Error = Infallible> + Clone + 'a {
    let forwarded_for = warp::header::<IpAddr>("X-FORWARDED-FOR")
        .or(warp::header("x-real-ip"))
        .unify()
        .map(Some)
        .or(warp::any().map(|| None))
        .unify();

    remote().and(forwarded_for).map(
        move |addr: Option<SocketAddr>, forwarded_for: Option<IpAddr>| {
            addr.map(|addr| {
                let ip = addr.ip();
                if trusted_proxies.contains(&ip) {
                    forwarded_for.unwrap_or(ip)
                } else {
                    ip
                }
            })
        },
    )
}
