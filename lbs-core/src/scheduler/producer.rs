use crate::{prelude::*, scheduler::worker::Maker};
use anyhow::Result;
use lyo::dispatcher::producer::Producer as ProducerTrait;

pub(crate) struct Producer<T: Maker>
where
    T: Send,
{
    maker: T,
}

impl<T: Maker + Send> Producer<T> {
    pub(crate) fn new(maker: T) -> Self {
        Self { maker }
    }
}

impl<T: Maker + Send> ProducerTrait<Action> for Producer<T> {
    async fn produce(&mut self) -> Result<Action> {
        let action = self.maker.produce().await?;
        Ok(action)
    }
}
