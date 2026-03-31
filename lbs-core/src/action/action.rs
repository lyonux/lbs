use crate::prelude::Rule;

pub enum ActionOption {
    Del,
    Add,
}

pub struct Action {
    pub rules: Vec<Rule>,
    pub option: ActionOption,
}
