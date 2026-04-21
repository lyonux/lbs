use anyhow::Result;
use lbs_core::scheduler::controller::Controller;
use lbs_core::scheduler::worker::{Maker, Worker};

/// Main rule manager that orchestrates iptables and tc rules
pub struct RuleManager<T: Worker, M: Maker> {
    controller: Controller<T, M>,
}

impl<T: Worker, M: Maker> RuleManager<T, M> {
    pub fn new(worker: T, maker: M) -> Result<Self> {
        let controller = Controller::new(worker, maker);
        Ok(Self { controller })
    }
    pub async fn run(&mut self) {
        self.controller.run().await;
    }
}
