//! sFlow-RT Key definition DSL parser.
//! See: https://sflow-rt.com/define_flow.php

use super::key_function::{CountryKeyFunction, GroupKeyFunction, UnknownKeyFunction};
use super::{KeyDefinition, KeyExpression, KeyFunction, KeyName, KEY_NAME_TO_VARIANT};

use anyhow::Context;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{alphanumeric1, char},
    combinator::{map, peek},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, preceded, terminated},
    Finish, IResult,
};

pub(crate) struct SflowRtKeyParserOptions {
    pub(crate) key_def_sep: char,
    pub(crate) fn_arg_sep: char,
    pub(crate) fn_nest_open: char,
    pub(crate) fn_nest_close: char,
}

pub(crate) const KEY_PARSEOPTS: SflowRtKeyParserOptions = SflowRtKeyParserOptions {
    key_def_sep: ',',
    fn_arg_sep: ':',
    fn_nest_open: '[',
    fn_nest_close: ']',
};

// parser: general purpose

#[allow(dead_code)]
fn parse_noop(input: &str) -> IResult<&str, &str> {
    Ok((input, ""))
}

fn alphanumeric1_or_underscore(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)
}

// parser: key name

fn parse_key_name_or_unknown(input: &str) -> IResult<&str, KeyName> {
    let (input, key_name) = alphanumeric1(input)?;
    let key_name = KEY_NAME_TO_VARIANT
        .get(key_name)
        .cloned()
        .unwrap_or_else(|| KeyName::Unknown(key_name.to_string()));
    Ok((input, key_name))
}

/// Parse a known key name. This function succeeds (advancing the input and returning
/// `Some`) only if it is able to recognize a key name from a known list. This
/// function guarantees that if it returns `Some(key_name)`, then `key_name` is *not*
/// a value of the `KeyName::Unknown` variant.
fn _parse_key_name_known(input: &str) -> IResult<&str, Option<KeyName>> {
    let (input, key_name_str) = peek(alphanumeric1)(input)?;
    if let Some(key_name) = KEY_NAME_TO_VARIANT.get(key_name_str) {
        let (input, _) = tag(key_name_str)(input)?;
        return Ok((input, Some((*key_name).clone())));
    }
    Ok((input, None))
}

// parser: key functions

fn _parse_key_function_name_from_separator<'a>(
    separator: char,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    terminated(parse_key_function_name, char(separator))
}

fn parse_key_function_name(input: &str) -> IResult<&str, &str> {
    alphanumeric1(input)
}

fn parse_key_function_argument(input: &str) -> IResult<&str, KeyExpression> {
    alt((
        delimited(
            char(KEY_PARSEOPTS.fn_nest_open),
            map(parse_key_function, KeyExpression::KeyFunction),
            char(KEY_PARSEOPTS.fn_nest_close),
        ),
        map(parse_key_name_or_unknown, KeyExpression::KeyName),
    ))(input)
}

fn parse_key_function_arguments(
    input: &str,
    leading_separator: bool,
) -> IResult<&str, Vec<KeyExpression>> {
    if leading_separator {
        many1(preceded(
            char(KEY_PARSEOPTS.fn_arg_sep),
            parse_key_function_argument,
        ))(input)
    } else {
        separated_list1(char(KEY_PARSEOPTS.fn_arg_sep), parse_key_function_argument)(input)
    }
}

fn parse_key_function(input: &str) -> IResult<&str, KeyFunction> {
    // Here, we require that each key function sub-combinator must parse its own
    // function name. but, since we need to know which function name is starting in
    // order to dispatch, we use `peek()`.
    //
    // Note that the `_parse_key_function_name_from_separator` approach is how we
    // determine if this input is the start of a key function call at all. This
    // *requires* that key functions have at least one argument; otherwise, it's
    // probably just an unrecognized flow key name.
    let (input, function_name) = peek(_parse_key_function_name_from_separator(
        KEY_PARSEOPTS.fn_arg_sep,
    ))(input)?;
    // Again, the remaining input starts with the function name! We only peeked above.
    match function_name {
        "group" => {
            let (input, kf) =
                GroupKeyFunction::parse_key_function(input, KEY_PARSEOPTS.fn_arg_sep)?;
            Ok((input, kf.into()))
        }
        "country" => {
            let (input, kf) =
                CountryKeyFunction::parse_key_function(input, KEY_PARSEOPTS.fn_arg_sep)?;
            Ok((input, kf.into()))
        }
        _ => {
            let (input, kf) =
                UnknownKeyFunction::parse_key_function(input, KEY_PARSEOPTS.fn_arg_sep)?;
            Ok((input, kf.into()))
        }
    }
}

pub(crate) trait KeyFunctionParser {
    type Output;
    fn parse_key_function(input: &str, separator: char) -> IResult<&str, Self::Output>;
}

impl KeyFunctionParser for UnknownKeyFunction {
    type Output = Self;
    fn parse_key_function(input: &str, separator: char) -> IResult<&str, Self::Output> {
        let (input, function_name) = _parse_key_function_name_from_separator(separator)(input)?;
        let (input, args) = parse_key_function_arguments(input, false)?;
        Ok((
            input,
            Self {
                function_name: function_name.to_string(),
                args,
            },
        ))
    }
}

impl KeyFunctionParser for GroupKeyFunction {
    type Output = Self;
    fn parse_key_function(input: &str, separator: char) -> IResult<&str, Self::Output> {
        const KEY_FUNCTION_NAME_GROUP: &str = "group";
        let (input, _) = terminated(tag(KEY_FUNCTION_NAME_GROUP), char(separator))(input)?;
        let (input, key) = parse_key_function_argument(input)?;
        let (input, group_names) =
            many0(preceded(char(separator), alphanumeric1_or_underscore))(input)?;
        let group_names: Vec<_> = group_names.into_iter().map(String::from).collect();
        Ok((
            input,
            GroupKeyFunction {
                key: Box::new(key),
                group_names,
            },
        ))
    }
}

impl KeyFunctionParser for CountryKeyFunction {
    type Output = Self;
    fn parse_key_function(input: &str, separator: char) -> IResult<&str, Self::Output> {
        const KEY_FUNCTION_NAME_COUNTRY: &str = "country";
        let (input, _) = terminated(tag(KEY_FUNCTION_NAME_COUNTRY), char(separator))(input)?;
        let (input, arg) = alphanumeric1(input)?;
        Ok((
            input,
            CountryKeyFunction {
                arg: arg.to_string(),
            },
        ))
    }
}

// parser: key expression

fn parse_key_expression(input: &str) -> IResult<&str, KeyExpression> {
    // Try parsing a key function first, then fall back to a key name
    let (input, key_expression) = map(parse_key_function, KeyExpression::KeyFunction)(input)
        .or_else(|_| map(parse_key_name_or_unknown, KeyExpression::KeyName)(input))?;
    Ok((input, key_expression))
}

// parser: key definition

pub fn parse_key_definition(input: &str) -> IResult<&str, KeyDefinition> {
    map(
        separated_list1(char(KEY_PARSEOPTS.key_def_sep), parse_key_expression),
        |keys: Vec<KeyExpression>| KeyDefinition { keys },
    )(input)
}

/// Take a `nom` parser's results and do the appropriate conversions and cloning that
/// yields an owned `anyhow` result (that doesn't require the input's data to have any
/// specific lifetime).
pub fn finish_nom_parse<T>(result: IResult<&str, T>) -> anyhow::Result<(String, T)> {
    match result.finish() {
        core::result::Result::Ok((s, key_definition)) => {
            anyhow::Result::Ok((s.to_owned(), key_definition))
        }
        core::result::Result::Err(e) => anyhow::Result::Err(anyhow::anyhow!(e.to_string()))
            .context("parsing a flow key definition"),
    }
}

// tests //////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case("ipsource", true, Some(KeyName::IpSource))]
    #[case("ipdestination", true, Some(KeyName::IpDestination))]
    #[case("unknownkey", false, None)]
    #[case("ip6source", true, Some(KeyName::Ip6Source))]
    #[case("ip5source", false, None)]
    fn test_parse_key_name(
        #[case] key_name: &str,
        #[case] is_known: bool,
        #[case] expected: Option<KeyName>,
    ) {
        if is_known {
            let expected: KeyName =
                expected.expect("known test cases should include an `expected` value");
            assert_eq!(
                _parse_key_name_known(key_name),
                Ok(("", Some(expected.clone())))
            );
            assert_eq!(
                parse_key_name_or_unknown(key_name),
                Ok(("", expected.clone()))
            );
        } else {
            assert_eq!(_parse_key_name_known(key_name), Ok((key_name, None)));
            assert_eq!(
                parse_key_name_or_unknown(key_name),
                Ok(("", KeyName::Unknown(key_name.to_string())))
            );
        }
    }

    #[test]
    fn test_parse_key_function() {
        // key function: country //////////////////////////////////////////////////////
        assert_eq!(
            parse_key_function("country:ipsource"),
            Ok((
                "",
                KeyFunction::from(CountryKeyFunction {
                    arg: "ipsource".to_string()
                })
            ))
        );

        // key function: group ////////////////////////////////////////////////////////
        // key function: group, arity 1

        assert_eq!(
            parse_key_function("group:ipdestination:gro_up1"),
            Ok((
                "",
                KeyFunction::Group(GroupKeyFunction {
                    key: Box::new(KeyExpression::KeyName(KeyName::IpDestination)),
                    group_names: vec!["gro_up1".to_string()]
                })
            ))
        );
        // key function: group, arity 2
        assert_eq!(
            parse_key_function("group:ipsource:gro_up1:group2"),
            Ok((
                "",
                KeyFunction::Group(GroupKeyFunction {
                    key: Box::new(KeyExpression::KeyName(KeyName::IpSource)),
                    group_names: vec!["gro_up1".to_string(), "group2".to_string()]
                })
            ))
        );
        // key function: group, arity 3
        assert_eq!(
            parse_key_function("group:ipsource:gro_up1:group2:_GROUP_THr33_"),
            Ok((
                "",
                KeyFunction::Group(GroupKeyFunction {
                    key: Box::new(KeyExpression::KeyName(KeyName::IpSource)),
                    group_names: vec![
                        "gro_up1".to_string(),
                        "group2".to_string(),
                        "_GROUP_THr33_".to_string()
                    ]
                })
            ))
        );

        // key function: unknown //////////////////////////////////////////////////////

        // key function: unknown, arity 1, basic
        assert_eq!(
            parse_key_function("unknownfunc:ipdestination"),
            Ok((
                "",
                KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![KeyExpression::KeyName(KeyName::IpDestination)],
                })
            ))
        );

        // key function: unknown, arity 1, with nesting
        assert_eq!(
            parse_key_function("unknownfunc:[group:ipdestination:gro_up1:group2]"),
            Ok((
                "",
                KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![KeyExpression::KeyFunction(KeyFunction::Group(
                        GroupKeyFunction {
                            key: Box::new(KeyExpression::KeyName(KeyName::IpDestination)),
                            group_names: vec!["gro_up1".to_string(), "group2".to_string()]
                        }
                    ))]
                })
            ))
        );
    }

    #[test]
    fn test_parse_key_expression() {
        assert_eq!(
            parse_key_expression("ipsource"),
            Ok(("", KeyExpression::KeyName(KeyName::IpSource)))
        );
        assert_eq!(
            parse_key_expression("country:ipsource"),
            Ok((
                "",
                KeyExpression::KeyFunction(KeyFunction::Country(CountryKeyFunction {
                    arg: "ipsource".to_string()
                }))
            ))
        );
        assert_eq!(
            parse_key_expression("unknownfunc:[group:ipsource:group1:group2]"),
            Ok((
                "",
                KeyExpression::KeyFunction(KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![KeyExpression::KeyFunction(KeyFunction::Group(
                        GroupKeyFunction {
                            key: Box::new(KeyExpression::KeyName(KeyName::IpSource)),
                            group_names: vec!["group1".to_string(), "group2".to_string()]
                        }
                    ))]
                }))
            ))
        );
    }

    #[test]
    fn test_parse_unknown_key_function_with_various_arguments() {
        // Non-nested argument
        assert_eq!(
            parse_key_function("unknownfunc:ipdestination"),
            Ok((
                "",
                KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![KeyExpression::KeyName(KeyName::IpDestination)],
                })
            ))
        );

        // Nested argument using brackets
        assert_eq!(
            parse_key_function("unknownfunc:[group:ipdestination:group1:group2]"),
            Ok((
                "",
                KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![KeyExpression::KeyFunction(KeyFunction::Group(
                        GroupKeyFunction {
                            key: Box::new(KeyExpression::KeyName(KeyName::IpDestination)),
                            group_names: vec!["group1".to_string(), "group2".to_string()]
                        }
                    ))]
                })
            ))
        );

        // Combination of both nested and non-nested arguments
        assert_eq!(
            parse_key_function(
                "unknownfunc:ipdestination:[group:ipdestination:group1:group2]:unknownkey"
            ),
            Ok((
                "",
                KeyFunction::Unknown(UnknownKeyFunction {
                    function_name: "unknownfunc".to_string(),
                    args: vec![
                        KeyExpression::KeyName(KeyName::IpDestination),
                        KeyExpression::KeyFunction(KeyFunction::Group(GroupKeyFunction {
                            key: Box::new(KeyExpression::KeyName(KeyName::IpDestination)),
                            group_names: vec!["group1".to_string(), "group2".to_string()]
                        })),
                        KeyExpression::KeyName(KeyName::Unknown("unknownkey".to_string())),
                    ],
                })
            ))
        );
    }
}
