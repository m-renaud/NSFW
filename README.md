# NSFW

A nice and simple firewall.

*Note: This is a for fun project that I'm doing to learn Haskell.*

## Summary

NSFW is a very simple packet filtering firewall. It uses a
configuration that defines the log level, a firewall state that
defines blacklists, whitelists, sessions, and other information that
packet filtering rules may require when deciding what to do with a
packet.

Given this information, it takes a list of packets and will either
ACCEPT or DROP the packet base on the specified rules. Currently,
it only has a protocol and source IP blacklist, but the goal will be
to eventually  have multiple configurable rule chains, with rules that
takes previous packets and information into account.
