use crate::prelude::Action;
use crate::scheduler::worker::Worker;
use tracing::error;

pub(crate) struct Consumer<T: Worker> {
    worker: T,
}

impl<T: Worker> Consumer<T> {
    pub(crate) fn new(worker: T) -> Self {
        Self { worker }
    }
}

impl<T: Worker + Sync> lyo::prelude::Consumer<Action> for Consumer<T> {
    async fn consume(&self, action: &Action) {
        if let Err(e) = self.worker.consume(action).await {
            error!("Worker consume error: {:?}", e);
        }
    }
    async fn stop(&self) {
        if let Err(e) = self.worker.stop().await {
            error!("Worker stop error: {:?}", e);
        }
    }
}
