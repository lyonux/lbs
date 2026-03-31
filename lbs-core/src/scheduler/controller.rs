use crate::prelude::Action;
use crate::scheduler::consumer::Consumer as ConsumerStruct;
use crate::scheduler::producer::Producer as ProducerStruct;
use crate::scheduler::worker::Worker;
use anyhow::Result;
use lyo::prelude::{Consumer, Producer};

use tokio::select;
use tracing::info;

pub struct Controller<T: Worker> {
    consumer: Box<ConsumerStruct<T>>,
    producer: Box<ProducerStruct>,
}

impl<T: Worker + Send + Sync> Controller<T> {
    pub fn new(consumer: T) -> Self {
        let producer = Box::new(ProducerStruct::new());
        let consumer = Box::new(ConsumerStruct::new(consumer));
        Self {
            consumer: consumer,
            producer: producer,
        }
    }
    pub async fn publish(&mut self, act: Action) -> Result<()> {
        self.producer.publish(act).await
    }
    pub async fn run(&mut self) {
        info!("Controller running");
        loop {
            select! {
                act = self.producer.produce() => {
                    match act {
                        Ok(act) => {
                            self.consumer.consume(&act).await;
                        }
                        Err(_) => {
                            info!("Producer stopped");
                            self.consumer.stop().await;
                            break;
                        }
                    }
                }
            }
        }
    }
}
