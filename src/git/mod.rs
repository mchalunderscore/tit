pub(crate) mod http;
pub(crate) mod packetline;
#[allow(
    dead_code,
    reason = "some protocol tests import Git without the public HTTP routes"
)]
pub(crate) mod read;
pub(crate) mod receive_pack;
pub(crate) mod repository;
pub(crate) mod transport;
pub(crate) mod upload_pack;
