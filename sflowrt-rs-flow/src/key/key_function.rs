use super::{KeyExpression, KeyFunction};

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownKeyFunction {
    pub function_name: String,
    pub args: Vec<KeyExpression>,
}

impl From<UnknownKeyFunction> for KeyFunction {
    fn from(value: UnknownKeyFunction) -> Self {
        Self::Unknown(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GroupKeyFunction {
    pub key: Box<KeyExpression>,
    pub group_names: Vec<String>,
}

impl From<GroupKeyFunction> for KeyFunction {
    fn from(value: GroupKeyFunction) -> Self {
        Self::Group(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CountryKeyFunction {
    pub arg: String,
}

impl From<CountryKeyFunction> for KeyFunction {
    fn from(value: CountryKeyFunction) -> Self {
        Self::Country(value)
    }
}
