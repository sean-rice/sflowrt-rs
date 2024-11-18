/// sFlow-RT Flow key structures.
/// See: https://sflow-rt.com/define_flow.php
pub mod key_function;
pub mod key_parser;

use std::{collections::HashMap, sync::LazyLock};

use fnv::FnvBuildHasher;
use key_function::*;
#[cfg(test)]
use strum::EnumCount;

/// A key expression. Flows are defined from (and bucketed based on) a vector of key
/// expressions. Contains either a plain key name, or a key value function expression.
///
/// See [sFlow-RT's documentation on Defining Flows](https://sflow-rt.com/define_flow.php).
#[derive(Clone, Debug, PartialEq)]
pub enum KeyExpression {
    KeyName(KeyName),
    KeyFunction(KeyFunction),
}

impl From<KeyName> for KeyExpression {
    fn from(value: KeyName) -> Self {
        Self::KeyName(value)
    }
}

impl From<KeyFunction> for KeyExpression {
    fn from(value: KeyFunction) -> Self {
        Self::KeyFunction(value)
    }
}

/// A flow key. This is an aspect of the network-level information we can capture,
/// modify with key value functions, and then categorize flows by.
///
/// See [sFlow-RT's documentation on Flow Keys](https://sflow-rt.com/define_flow.php#keys).
#[cfg_attr(test, derive(EnumCount))]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum KeyName {
    IpSource,
    IpDestination,

    /*
        IP version 6: (Key definition name, Example, Comment)
    */
    /// "ip6_offset", 14, IPv6 header offset from start of packet
    Ip6Offset,
    /// "ip6tos", 01100000, type of service bits
    Ip6TOS,
    /// "ip6ecn", 00, explicit congestion notification bits
    Ip6ECN,
    /// "ip6dscp", 0, differentiated services code point
    Ip6DSCP,
    /// "ip6dscpname", be(0), differentiated services code point name
    Ip6DSCPName,
    /// "ip6flowlabel", 501244, flow label
    Ip6FlowLabel,
    /// "ip6ttl", 63, time to live
    Ip6TTL,
    /// "ip6source", FE80::104C:51DF:4458:E00A, source address
    Ip6Source,
    /// "ip6destination", FE80::A00:27FF:FEB8:326D, destination address
    Ip6Destination,
    /// "ip6bytes", 60, payload bytes
    Ip6Bytes,
    /// "ip6extensions", 0, list of next header values for extension headers
    Ip6Extensions,
    /// "ip6fragoffset", 0, fragment offset
    Ip6FragmentOffset,
    /// "ip6fragm", false, fragment m flag
    Ip6FragmentMFlag,
    /// "ip6nexthdr", 17, next header
    Ip6NextHeader,

    /* Add more known key names here */

    /*
        Unknown
    */
    /// An unknown/unrecognized key name.
    Unknown(String),
}

impl KeyName {
    pub fn to_sflowrt_key_name(&self) -> Option<&'static str> {
        match self {
            KeyName::Unknown(ref _ukn) => None,
            _ => KEY_VARIANT_TO_NAME.get(self).copied(),
        }
    }

    pub fn from_sflowrt_key_name(key_name: &str) -> Option<Self> {
        KEY_NAME_TO_VARIANT.get(key_name).map(|k| (*k).clone())
    }
}

/// A hashmap from the sFlow-RT key name as a string to the key name enum value.
///
/// See also: the inverse, [`KEY_INVARIANT_TO_NAME`].
static KEY_NAME_TO_VARIANT: phf::Map<&'static str, KeyName> = phf::phf_map! {
    /*
        IP
    */
    "ipsource" => KeyName::IpSource,
    "ipdestination" => KeyName::IpDestination,
    /*
        IP version 6
    */
    "ip6_offset" => KeyName::Ip6Offset,
    "ip6tos" => KeyName::Ip6TOS,
    "ip6ecn" => KeyName::Ip6ECN,
    "ip6dscp" => KeyName::Ip6DSCP,
    "ip6dscpname" => KeyName::Ip6DSCPName,
    "ip6flowlabel" => KeyName::Ip6FlowLabel,
    "ip6ttl" => KeyName::Ip6TTL,
    "ip6source" => KeyName::Ip6Source,
    "ip6destination" => KeyName::Ip6Destination,
    "ip6bytes" => KeyName::Ip6Bytes,
    "ip6extensions" => KeyName::Ip6Extensions,
    "ip6fragoffset" => KeyName::Ip6FragmentOffset,
    "ip6fragm" => KeyName::Ip6FragmentMFlag,
    "ip6nexthdr" => KeyName::Ip6NextHeader,
};

/// A hashmap from key name enum value to the sFlow-RT key name as a string.
///
/// See also: the inverse, [`KEY_NAME_TO_INVARIANT`].
static KEY_VARIANT_TO_NAME: LazyLock<HashMap<KeyName, &'static str, FnvBuildHasher>> =
    LazyLock::new(|| {
        let mut map: HashMap<KeyName, &'static str, FnvBuildHasher> =
            HashMap::with_capacity_and_hasher(KEY_NAME_TO_VARIANT.len(), Default::default());
        for (k, v) in KEY_NAME_TO_VARIANT.entries() {
            map.insert((*v).clone(), *k);
        }
        map
    });

/// A flow key function. Operates on key names (and/or other potentially literal-valued
/// arguments) to modify the key instance of a flow before it is categorized.
///
/// See [sFlow-RT's documentation on Key Functions](https://sflow-rt.com/define_flow.php#keyfunctions).
#[derive(Clone, Debug, PartialEq)]
pub enum KeyFunction {
    Group(GroupKeyFunction),
    Country(CountryKeyFunction),
    // Add more known key value functions here
    /// An unknown key function.
    Unknown(UnknownKeyFunction),
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyDefinition {
    keys: Vec<KeyExpression>,
}

// tests //////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod tests {
    use strum::EnumCount;

    use super::{KeyName, KEY_NAME_TO_VARIANT};
    use crate::key::KEY_VARIANT_TO_NAME;

    /// Test that the two (complementary) mappings between known sFlow-RT keys as
    /// enum variants in `KeyName` and as sFlow-RT DSL key name strings in the keys of
    /// `KEY_NAME_TO_VARIANT` are both exhaustive (except for `KeyName::Unknown`), and
    /// therefore both contain the same number of entries and that each of those
    /// entries is unique.
    ///
    /// This test's implementation relies on `KeyName::to_sflowrt_key_name()` being
    /// exhaustive, which is ensured in the implementation via a `match` statement over
    /// `KeyName` variants which the Rust compiler itself ensures is exhaustive (as
    /// long as no `_` or `default` match arms are added).
    ///
    /// This function needs to check several rules:
    ///
    /// 1) That no `KeyName::Unknown` variants are in `KEY_NAME_TO_VARIANT`; this
    /// should be impossible because by definition there should be no corresponding
    /// sFlow-RT key string for our unknown variant which stores unrecognized keys.
    ///
    /// 2) That `KEY_NAME_TO_VARIANT` and `KEY_VARIANT_TO_NAME` are fully
    /// complementary, meaning we can do round-tripping though both for all entries,
    /// plus basic tests like they are the same length.
    ///
    /// 3) That either `KEY_NAME_TO_VARIANT` or `KEY_VARIANT_TO_NAME` are exhaustive
    /// over all variants of `KeyName` *except* for `KeyName::Unknown`. If one is,
    /// we know the other is as well as long as rule (2) holds.
    ///
    /// Because this is a critical test to have correct, we will verify each rule in
    /// sequence rather than combining logic.
    #[test]
    fn test_key_name_mappings() {
        // testing rule (1) ///////////////////////////////////////////////////////////
        // ensure there are no `KeyName::Unknown` variants in `KEY_NAME_TO_VARIANT`.
        fn _check_not_unknown_variant(key_name: &KeyName) -> anyhow::Result<()> {
            match key_name {
                KeyName::Unknown(ref kn) => Err(anyhow::anyhow!(
                    "Found `KeyName::Unknown` variant with key name `{kn}`"
                )),
                _ => Ok(()),
            }
        }
        for (_, name_variant) in KEY_NAME_TO_VARIANT.entries() {
            _check_not_unknown_variant(name_variant).expect(
                "mapping `KEY_NAME_TO_VARIANT` should not contain a `KeyName::Unknown` variant",
            );
        }
        // testing rule (2) ///////////////////////////////////////////////////////////
        // ensure `KEY_NAME_TO_VARIANT` and `KEY_VARIANT_TO_NAME` are complementary.
        // we can prove they are complementary by independently proving:
        // 2.1) each of the mappings' key-value pairs is present in the others' as a
        // pair-value entry.
        // 2.2) each of the mappings have the same number of entries.
        // testing rule (2.1)(a), KEY_NAME_TO_VARIANT -> KEY_VARIANT_TO_NAME
        for (name_str, name_variant) in KEY_NAME_TO_VARIANT.entries() {
            let name_str = *name_str;
            let inv_str = KEY_VARIANT_TO_NAME.get(name_variant)
                .map(|s| *s)
                .expect(&format!("name variant {name_variant:?} from `KEY_NAME_TO_VARIANT[\"{name_str}\"]` should be present in `KEY_VARIANT_TO_NAME`"));
            assert_eq!(name_str, inv_str, "failed roundtrip: `KEY_NAME_TO_VARIANT[\"{name_str}\"] => {name_variant:?}` used to perform lookup `KEY_VARIANT_TO_NAME[{name_variant:?}]` gave \"{inv_str}\", expected \"{name_str}\"");
            let inv_inv_variant = KEY_NAME_TO_VARIANT.get(inv_str)
                .map(|v| v.clone())
                .expect(&format!("name str \"{inv_str:?}\" from round-trip should be present in `KEY_NAME_TO_VARIANT`"));
            assert_eq!(name_variant, &inv_inv_variant, "failed roundtrip: name variant {name_variant:?} from `KEY_NAME_TO_VARIANT[\"{name_str}\"]` did not double-roundtrip; got `{inv_inv_variant:?}`")
        }
        // testing rule (2.1)(b), KEY_VARIANT_TO_NAME -> KEY_NAME_TO_VARIANT
        for (name_variant, name_str) in KEY_VARIANT_TO_NAME.iter() {
            let name_str = *name_str;
            let inv_variant = KEY_NAME_TO_VARIANT.get(name_str)
                .map(|v| v.clone())
                .expect(&format!("name str \"{name_str}\" from `KEY_VARIANT_TO_NAME[{name_variant:?}]` should be present in `KEY_NAME_TO_VARIANT`"));
            assert_eq!(name_variant, &inv_variant, "failed roundtrip: `KEY_VARIANT_TO_NAME[{name_variant:?}] => \"{name_str}\"` used to perform lookup `KEY_NAME_TO_VARIANT[\"{name_str}\"]` gave `{inv_variant:?}`, expected `{name_variant:?}`");
            let inv_inv_str = KEY_VARIANT_TO_NAME.get(&inv_variant)
                .map(|s| *s)
                .expect(&format!("name variant `{inv_variant:?}` from round-trip should be present in `KEY_VARIANT_TO_NAME`"));
            assert_eq!(name_str, inv_inv_str, "failed roundtrip: name str \"{name_str}\" from `KEY_VARIANT_TO_NAME[{name_variant:?}]` did not double-roundtrip; got \"{inv_inv_str:?}\"");
        }
        // testing rule (2.2)
        let n2v_len = KEY_NAME_TO_VARIANT.len();
        let v2n_len = KEY_VARIANT_TO_NAME.len();
        assert_eq!(
            n2v_len, v2n_len,
            "Key name/variant mappings have different lengths. n2v: {n2v_len}, v2n: {v2n_len}"
        );

        // testing rule (3) ///////////////////////////////////////////////////////////
        // ensure `KEY_VARIANT_TO_NAME` is exhaustive (besides `KeyName::Unknown`).
        let n_non_unknown_variants = KeyName::COUNT - 1;
        assert_eq!(n2v_len, n_non_unknown_variants, "mapping `KEY_NAME_TO_VARIANT`'s length ({n2v_len}) does not match the number of non-`Unknown` variants of `KeyName` ({n_non_unknown_variants})");
        assert_eq!(v2n_len, n_non_unknown_variants, "mapping `KEY_VARIANT_TO_NAME`'s length ({v2n_len}) does not match the number of non-`Unknown` variants of `KeyName` ({n_non_unknown_variants})");
    }
}
