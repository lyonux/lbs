use crate::prelude::Rule;

#[derive(Debug, Clone, PartialEq)]
pub enum ActionOption {
    Del,
    Add,
    Reconcile,
}

#[derive(Debug)]
pub struct Action {
    pub rules: Vec<Rule>,
    pub option: ActionOption,
}

impl Action {
    pub fn new(rules: Vec<Rule>, option: ActionOption) -> Self {
        Self { rules, option }
    }
}
