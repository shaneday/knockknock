#!/bin/bash
set -euo pipefail
export LC_ALL=C

# Keep rules knocked or used for SSH in the last 30 days.
cutoff=$(date -u -d '30 days ago' +%Y%m%d)
rules=$(ufw show added)
recent=$(journalctl --since '30 days ago' --no-pager -o cat _COMM=sshd _COMM=sshd-session |
    awk '/^Accepted .* from / { for (i = 1; i < NF; i++) if ($i == "from") print $(i + 1) }')
if [[ -z "$recent" ]]; then
    echo 'No recent successful SSH logins found; leaving rules unchanged.' >&2
    exit 1
fi

pattern="^ufw allow from ([0-9a-fA-F:.]+) to any port 22 comment 'knockknock ([0-9]{8})'$"
while IFS= read -r rule; do
    [[ $rule =~ $pattern ]] || continue
    ip=${BASH_REMATCH[1]}
    stamp=${BASH_REMATCH[2]}
    [[ $stamp < $cutoff ]] || continue
    if ! grep -qxF -- "$ip" <<< "$recent"; then
        ufw --force delete allow from "$ip" to any port 22
    fi
done <<< "$rules"
