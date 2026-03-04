#!/usr/bin/env python3
"""Fix VPS node configuration: correct seed peers and P2P config."""
import json

SEED_NODE = "/ip6/2a0d:3341:b16b:4808:5054:ff:fea7:bab0/tcp/4001/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd"
SEED_QUIC = "/ip6/2a0d:3341:b16b:4808:5054:ff:fea7:bab0/udp/4001/quic-v1/p2p/12D3KooWLqikBBCRhCZ2MgSYG3R579BNUgrN5E6dZnYSEYdmAKTd"

# Fix node_config.json
with open("/home/node_config.json", "r") as f:
    cfg = json.load(f)
cfg["seed_peers"] = [SEED_NODE, SEED_QUIC]
with open("/home/node_config.json", "w") as f:
    json.dump(cfg, f, indent=2)

# Fix p2p_config.json
with open("/home/stone_data/p2p_config.json", "r") as f:
    p2p = json.load(f)
p2p["listen_addr"] = "/ip4/0.0.0.0/tcp/4001"
p2p["bootstrap_nodes"] = [SEED_NODE, SEED_QUIC]
p2p["relay_nodes"] = [SEED_NODE]
with open("/home/stone_data/p2p_config.json", "w") as f:
    json.dump(p2p, f, indent=2)

print("OK: VPS config gefixt")
print("  seed_peers:", [SEED_NODE[:50] + "..."])
print("  listen_addr: /ip4/0.0.0.0/tcp/4001")
