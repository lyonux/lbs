use crate::prelude::Action;
use anyhow::Result;
use std::future::Future;

pub trait Worker {
    fn consume(&self, action: &Action) -> impl Future<Output = Result<(), anyhow::Error>> + Send;
    fn stop(&self) -> impl Future<Output = Result<(), anyhow::Error>> + Send;
}
