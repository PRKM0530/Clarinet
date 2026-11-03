#!/usr/bin/env bash
# Read-only checks. Changes nothing. Run as a normal user:  bash tests/lab/lab_preflight.sh
echo "== tools"; for t in ip nft tc nmap iperf3 curl ping python3; do printf "%-8s" $t; command -v $t || echo MISSING; done
echo "== kernel modules available (loaded or loadable)"
for m in nf_tables sch_htb ifb sch_netem veth bridge; do
  if lsmod | grep -q "^$m "; then echo "$m: loaded"; elif modinfo "$m" >/dev/null 2>&1; then echo "$m: loadable"; else echo "$m: NOT AVAILABLE"; fi
done
echo "== host state (only reported, never changed)"
printf "firewalld: "; systemctl is-active firewalld 2>&1
printf "SELinux:   "; getenforce 2>&1
echo "host ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "existing lab namespaces:"; ip netns list 2>/dev/null | grep '^clb-' || echo "  none"
echo "== python venv"; ls ~/clarinet-venv/bin/python && ~/clarinet-venv/bin/python -c "import scapy" 2>&1 | tail -1
