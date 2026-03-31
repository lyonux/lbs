use crate::prelude::*;
use anyhow::Result;
use tokio;

pub(crate) struct Producer {
    sender: tokio::sync::mpsc::UnboundedSender<Action>,
    receiver: tokio::sync::mpsc::UnboundedReceiver<Action>,
}

impl Producer {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<Action>();
        Self { sender, receiver }
    }
    pub(crate) async fn publish(&self, action: Action) -> Result<()> {
        self.sender.send(action).map_err(|e| anyhow::anyhow!(e))
    }
}

impl lyo::prelude::Producer<Action> for Producer {
    async fn produce(&mut self) -> Result<Action> {
        match self.receiver.recv().await {
            Some(item) => Ok(item),
            None => Err(anyhow::anyhow!("Producer closed")),
        }
    }
}
