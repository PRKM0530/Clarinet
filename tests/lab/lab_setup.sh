#!/usr/bin/env bash
# Creates the throw-away lab. Needs root:  sudo bash tests/lab/lab_setup.sh
# Touches ONLY namespaces named clb-* (and the veth/bridge devices inside them).
# The host's interfaces, routes, firewall and sysctls are never modified.
#
#   clb-internet (10.78.0.2, 203.0.113.10)  --veth--  clb-router (10.78.0.1 | br-lan 10.77.0.1)
#   br-lan inside clb-router connects: clb-a .11, clb-b .12, clb-attacker .66, clb-guest .30
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
ip netns list | grep -q '^clb-' && { echo "lab already exists; run lab_teardown.sh first"; exit 1; }

N() { ip netns exec "$@"; }
for ns in internet router a b attacker guest; do ip netns add clb-$ns; N clb-$ns ip link set lo up; done

# upstream link
ip link add clbw-r type veth peer name clbw-i
ip link set clbw-r netns clb-router; ip link set clbw-i netns clb-internet
N clb-router   ip addr add 10.78.0.1/30 dev clbw-r; N clb-router   ip link set clbw-r up
N clb-internet ip addr add 10.78.0.2/30 dev clbw-i; N clb-internet ip link set clbw-i up
N clb-internet ip addr add 203.0.113.10/32 dev lo
N clb-internet ip route add 10.77.0.0/24 via 10.78.0.1
N clb-router   ip route add default via 10.78.0.2

# LAN bridge inside the router namespace
N clb-router ip link add br-lan type bridge
N clb-router ip addr add 10.77.0.1/24 dev br-lan
N clb-router ip link set br-lan up
attach() {  # name  last-octet
  ip link add clbl-$1 type veth peer name clbc-$1
  ip link set clbl-$1 netns clb-router; ip link set clbc-$1 netns clb-$1
  N clb-router ip link set clbl-$1 master br-lan; N clb-router ip link set clbl-$1 up
  N clb-$1 ip link set clbc-$1 name eth0
  N clb-$1 ip addr add 10.77.0.$2/24 dev eth0; N clb-$1 ip link set eth0 up
  N clb-$1 ip route add default via 10.77.0.1
}
attach a 11; attach b 12; attach attacker 66; attach guest 30

# forwarding is a per-namespace sysctl: this affects clb-router only
N clb-router sysctl -qw net.ipv4.ip_forward=1

echo "== quick check"
N clb-a ping -c1 -W2 10.77.0.1 >/dev/null && echo "a -> router ok"
N clb-a ping -c1 -W2 203.0.113.10 >/dev/null && echo "a -> fake internet ok"
echo "lab ready. Show it with: ip netns list"
