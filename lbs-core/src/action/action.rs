use crate::prelude::Global;
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
    pub global: Global,
    pub option: ActionOption,
}

impl Action {
    pub fn new(rules: Vec<Rule>, global: Global, option: ActionOption) -> Self {
        Self {
            rules,
            global,
            option,
        }
    }
}
