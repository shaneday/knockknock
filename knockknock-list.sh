#!/bin/bash
set -euo pipefail
export LC_ALL=C

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
ufw status > "$work/rules"
if ! grep -qx 'Status: active' "$work/rules"; then
    echo 'UFW is inactive or its status could not be read.' >&2
    exit 1
fi
journalctl -u ssh.service -u sshd.service --since '30 days ago' --no-pager -o cat > "$work/logins"

awk '
    FILENAME == ARGV[1] {
        if ($1 == "Accepted" && $3 == "for" && $5 == "from" && $7 == "port" &&
            $4 ~ /^[[:alnum:]_.@-]+$/ && $6 ~ /^[0-9a-fA-F:.]+$/ && !seen[$6, $4]++)
            users[$6] = users[$6] (users[$6] ? "," : "") $4
        next
    }
    {
        if (NF < 6 || $(NF-2) != "#" || $(NF-1) != "knockknock" || length($NF) != 8 ||
            $NF !~ /^[0-9]+$/ || $1 !~ /^[0-9]+(\/tcp)?$/)
            next
        action = ($2 == "(v6)" ? $3 : $2)
        direction = ($2 == "(v6)" ? $4 : $3)
        ip = $(NF-3)
        if (action == "ALLOW" && (direction == "IN" || direction == ip) &&
            ip ~ /^[0-9a-fA-F:.]+$/)
            print $NF, ip, (users[ip] ? users[ip] : "-")
    }
' "$work/logins" "$work/rules" | sort -r
