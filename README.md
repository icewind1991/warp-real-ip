# wrap-real-ip

Warp filter to get the "real ip" of the remote client

This uses the "x-forwarded-for" or "x-real-ip" headers set by reverse proxies.
To stop clients from abusing these headers, only headers set by trusted remotes will be accepted.

## Example

```rust
use warp::Filter;
use warp_real_ip::real_ip;
use std::net::IpAddr;

let proxy_addr = [127, 10, 0, 1].into();
warp::any()
    .and(real_ip(vec![proxy_addr]))
    .map(|addr: Option<IpAddr>| format!("Hello {}", addr.unwrap()));
```