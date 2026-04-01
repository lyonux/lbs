use crate::scheduler::consumer::Consumer as ConsumerStruct;
use crate::scheduler::producer::Producer as ProducerStruct;
use crate::scheduler::worker::{Maker, Worker};
use lyo::prelude::{Consumer, Producer};

use tokio::select;
use tracing::info;

pub struct Controller<T: Worker, M: Maker + Send> {
    consumer: Box<ConsumerStruct<T>>,
    producer: Box<ProducerStruct<M>>,
}

impl<T: Worker + Send + Sync, M: Maker + Send> Controller<T, M> {
    pub fn new(consumer: T, maker: M) -> Self {
        let producer = Box::new(ProducerStruct::new(maker));
        let consumer = Box::new(ConsumerStruct::new(consumer));
        Self {
            consumer: consumer,
            producer: producer,
        }
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
