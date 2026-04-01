use crate::prelude::Action;
use lyo::prelude::Consumer;
use lyo::prelude::Producer;

pub trait Maker: Producer<Action> {}
pub trait Worker: Consumer<Action> {}
