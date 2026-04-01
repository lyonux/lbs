use crate::prelude::Action;
use crate::scheduler::worker::Worker;
use lyo::dispatcher::consumer::Consumer as ConsumerTrait;

pub(crate) struct Consumer<T: Worker> {
    worker: T,
}

impl<T: Worker> Consumer<T> {
    pub(crate) fn new(worker: T) -> Self {
        Self { worker }
    }
}

impl<T: Worker + Sync> ConsumerTrait<Action> for Consumer<T> {
    async fn consume(&self, action: &Action) {
        self.worker.consume(action).await;
    }
    async fn stop(&self) {
        self.worker.stop().await;
    }
}
