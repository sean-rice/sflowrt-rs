# `sflowrt-rs`

rust crates related to [sFlow-RT](https://sflow-rt.com/).

## crates / modules list

### crate [`sflowrt-rs-flow`](./sflowrt-rs-flow/)

a crate for working with sFlow-RT's flow construct. see
[sFlow-RT Doc: Defining Flows](https://sflow-rt.com/define_flow.php). in particular,
the [`sflowrt_flow::key::key_parser`](./sflowrt-rs-flow/src/key/key_parser.rs) module
contains the beginnings of a parser for sFlow-RT's key definition dsl, implemented via
the [`nom`](https://docs.rs/nom/latest/nom/) parser combinator library. the framework
for the language is in good shape, but there are many
[flow keys](https://sflow-rt.com/define_flow.php#keys) provided by sFlow-RT that i have
not yet implemented; the same is true for the
[key functions](https://sflow-rt.com/define_flow.php#keyfunctions).

### crate [`sflowrt-rs-cli`](./sflowrt-rs-cli/)

a crate the contains a cli + repl for the `sflowrt-rs` project. currently, it is just
a repl with a single command, `parse-key`, for interactively running the key
definition dsl langauge parser (implemented in the `sflowrt-rs-flow` crate).

a small demo of using `parse-key` (with a little output formatting):

```shell
$ cargo run sflowrt-rs-cli
sflowrt-rs-cli〉parse-key ip6destination,group:[country:ip6source]:trusted:bad:unknown
KeyDefinition { keys: [
    KeyName(Ip6Destination),
    KeyFunction(Group(GroupKeyFunction {
        key: KeyFunction(Country(CountryKeyFunction {
            arg: "ip6source"
        })),
        group_names: ["trusted", "bad", "unknown"]
    }))
] }
```

## why?

i'm trying to more fully immerse myself in rust programming. i wanted a toy project
that would allow me to focus on learning rust (as well as `nom`); i'm already pretty
familiar with sFlow-RT and thought building a parser for its flow key definition
language would be fun. it has been!
