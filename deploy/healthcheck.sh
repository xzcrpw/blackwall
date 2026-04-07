#!/bin/bash
# Blackwall Health Check — returns non-zero if any component is down

FAILED=0
REPORT=""

# Check blackwall daemon
if ! pidof blackwall > /dev/null 2>&1; then
    REPORT+="CRIT: blackwall not running\n"
    FAILED=1
fi

# Check XDP attached
if ! ip link show | grep -q xdp; then
    REPORT+="CRIT: XDP not attached to any interface\n"
    FAILED=1
fi

# Check tarpit
if ! pidof tarpit > /dev/null 2>&1; then
    REPORT+="WARN: tarpit not running\n"
fi

# Check hivemind
if ! pidof hivemind > /dev/null 2>&1; then
    REPORT+="WARN: hivemind not running\n"
fi

# Check hivemind-api
if ! ss -tlnp | grep -q 8090; then
    REPORT+="WARN: hivemind-api not listening on 8090\n"
fi

# Check peer connectivity (if hivemind-api responds)
STATS=$(curl -s --max-time 3 http://127.0.0.1:8090/stats 2>/dev/null)
if [ -n "$STATS" ]; then
    PEERS=$(echo "$STATS" | grep -o '"peer_count":[0-9]*' | cut -d: -f2)
    if [ "${PEERS:-0}" -eq 0 ]; then
        REPORT+="WARN: hivemind has 0 peers\n"
    fi
fi

# Check Docker (if applicable)
if command -v docker &> /dev/null; then
    DOCKER_COUNT=$(docker ps -q 2>/dev/null | wc -l)
    if [ "$DOCKER_COUNT" -eq 0 ]; then
        REPORT+="CRIT: No Docker containers running (expected >0)\n"
        FAILED=1
    fi
fi

if [ $FAILED -eq 1 ]; then
    echo -e "BLACKWALL HEALTH: CRITICAL\n$REPORT"
    exit 1
elif [ -n "$REPORT" ]; then
    echo -e "BLACKWALL HEALTH: DEGRADED\n$REPORT"
    exit 0
else
    echo "BLACKWALL HEALTH: OK"
    exit 0
fi
