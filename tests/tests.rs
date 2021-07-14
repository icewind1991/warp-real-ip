use std::net::IpAddr;
use warp::Filter;
use warp_real_ip::real_ip;

fn serve<'a>(trusted: Vec<IpAddr>) -> impl Filter<Extract = (String,)> + 'a {
    warp::any()
        .and(real_ip((&trusted).into()))
        .map(|addr: Option<IpAddr>| addr.unwrap().to_string())
}

#[tokio::test]
async fn test_not_forwarded() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .reply(&serve(vec![]))
        .await;
    assert_eq!(res.body(), "1.2.3.4");
}

#[tokio::test]
async fn test_not_trusted() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("x-forwarded-for", "10.10.10.10")
        .reply(&serve(vec![]))
        .await;
    assert_eq!(res.body(), "1.2.3.4");
}

#[tokio::test]
async fn test_trusted() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("x-forwarded-for", "10.10.10.10")
        .reply(&serve(vec![remote]))
        .await;
    assert_eq!(res.body(), "10.10.10.10");
}

#[tokio::test]
async fn test_nested_denied() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("x-forwarded-for", "10.10.10.10, 11.11.11.11")
        .reply(&serve(vec![remote]))
        .await;
    assert_eq!(res.body(), "11.11.11.11");
}

#[tokio::test]
async fn test_nested_allowed() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("x-forwarded-for", "10.10.10.10, 11.11.11.11")
        .reply(&serve(vec![remote, [10, 10, 10, 10].into()]))
        .await;
    assert_eq!(res.body(), "11.11.11.11");
}

#[tokio::test]
async fn test_trusted_forwarded() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("forwarded", "for=10.10.10.10")
        .reply(&serve(vec![remote]))
        .await;
    assert_eq!(res.body(), "10.10.10.10");
}

#[tokio::test]
async fn test_trusted_forwarded_no_for() {
    let remote: IpAddr = [1, 2, 3, 4].into();
    let res = warp::test::request()
        .remote_addr((remote, 80).into())
        .header("forwarded", "by=11.11.11.11")
        .reply(&serve(vec![remote]))
        .await;
    assert_eq!(res.body(), "1.2.3.4");
}
