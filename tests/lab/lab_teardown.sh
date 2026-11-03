#!/usr/bin/env bash
# Removes everything lab_setup.sh made. Deleting a namespace removes the devices inside it.
# Needs root:  sudo bash tests/lab/lab_teardown.sh
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
pkill -f "clarinet-lab" 2>/dev/null || true
for ns in $(ip netns list | awk '/^clb-/{print $1}'); do
  ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del $ns
done
echo "remaining clb namespaces: $(ip netns list | grep -c '^clb-')"
