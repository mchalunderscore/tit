pub(crate) mod http;
pub(crate) mod packetline;
#[allow(
    dead_code,
    reason = "M2.3 establishes repository reads before the HTTP handlers call them"
)]
pub(crate) mod read;
pub(crate) mod receive_pack;
pub(crate) mod repository;
pub(crate) mod transport;
pub(crate) mod upload_pack;
