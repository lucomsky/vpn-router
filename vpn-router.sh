#!/usr/bin/env bash
# vpn-router.sh - temporarily share an already-running VPN tunnel with a device
# (typically a router's WAN port) plugged into this laptop's Ethernet port.
#
#   Internet <-(VPN tunnel)- laptop -[Ethernet]- router WAN -> router LAN/Wi-Fi clients
#
# Target: Ubuntu 24.04 (NetworkManager, nftables, optional ufw/docker).
#
# All changes are runtime-only and are reverted when the script exits:
#   - normal exit ("q"), Ctrl-C, terminal closed, error in the script;
#   - kill -9 of the script: a detached watchdog process reverts everything;
#   - reboot / power loss: nothing was written to disk, so nothing persists.
# Every change is recorded in an undo journal (/run/vpnrouter_tmp/undo) before
# it is applied; the journal is replayed in reverse order on cleanup.
#
# Kill switch: clients' traffic is only ever forwarded out of the chosen VPN
# interface. If the VPN goes down, client traffic is blocked (never leaks via
# Wi-Fi) and resumes automatically when the tunnel comes back. IPv6 from the
# downstream port is blocked entirely. DNS for clients is served by a temporary
# dnsmasq whose upstream queries are pinned to the VPN interface.
#
# Optional split routing for Russia: destinations in Russian IP ranges (RIPE
# country list, downloaded at start) and IPs of Russian domains (.ru, .su, .рф,
# well-known Russian services, resolved via the ISP's DNS) bypass the VPN and go
# directly out of the original uplink (Wi-Fi, USB modem or wired). Everything
# else still goes only through the VPN. Extra entries can be put next to the script:
#   direct-domains.txt  one domain per line (subdomains included), # comments
#   direct-cidrs.txt    one IPv4 address or CIDR per line, # comments
#   ru-cidrs.txt        offline fallback for the Russian IP list if download fails
#
# Usage:
#   sudo ./vpn-router.sh            interactive setup
#   sudo ./vpn-router.sh --cleanup  revert leftovers of a previous run (normally automatic)

set -Eeuo pipefail

readonly NAME=vpnrouter_tmp
readonly STATE_DIR=/run/$NAME
readonly JOURNAL=$STATE_DIR/undo
readonly LOCK=/run/$NAME.lock
readonly LOG=$STATE_DIR/dnsmasq.log
SELF=$(readlink -f "$0")
readonly SELF
readonly SELF_DIR=${SELF%/*}
readonly MARK=0x5255                       # fwmark/ctmark of "direct" (Russian) traffic
readonly RU_CIDR_URLS=(
    'https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix'
    'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone'
)
# Russian TLDs (рф, москва, дети, рус) and Russian services living on other TLDs.
readonly DEFAULT_DIRECT_DOMAINS=(
    ru su xn--p1ai xn--80adxhks xn--d1acj3b xn--p1acf moscow tatar
    yandex.net yandex.com yastatic.net yandexcloud.net yandex.cloud
    vk.com vk.me userapi.com vkuser.net vkuservideo.net vk-cdn.net mycdn.me
    avito.st 2gis.com sberbank.com
)

# ---------------------------------------------------------------- output ----

if [[ -t 1 ]]; then
    B=$'\e[1m' R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
else
    B='' R='' G='' Y='' C='' N=''
fi
info() { printf '%s\n' "${C}==>${N} $*"; }
ok()   { printf '%s\n' "${G}✔${N} $*"; }
warn() { printf '%s\n' "${Y}!${N} $*" >&2; }
die()  { printf '%s\n' "${R}✘ $*${N}" >&2; exit 1; }

ask() { # ask VAR "prompt" [default]
    local __var=$1 __prompt=$2 __def=${3:-} __ans
    if [[ -n $__def ]]; then __prompt+=" [${__def}]"; fi
    read -rp "$__prompt: " __ans || die "input closed"
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

confirm() { # confirm "question" -> 0 on yes (default yes)
    local a
    read -rp "$1 [Y/n]: " a || die "input closed"
    [[ -z $a || $a == [yY]* ]]
}

# ---------------------------------------------------------- undo journal ----

# Record a command (argv) that reverts a change. Recorded BEFORE the change is
# made, so an interruption at any point can still be undone. Undo commands must
# be harmless if the change was never applied.
undo_push() {
    local q
    printf -v q '%q ' "$@"
    printf '%s\n' "$q" >>"$JOURNAL"
}

kill_pidfile() { # used from the journal
    local pid
    pid=$(cat "$1" 2>/dev/null) || return 0
    [[ -n $pid ]] && kill "$pid" 2>/dev/null || return 0
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.2; done
    kill -9 "$pid" 2>/dev/null || true
}

run_cleanup() {
    [[ -f $JOURNAL ]] || return 0
    exec 9>"$LOCK"
    flock 9
    if [[ -f $JOURNAL ]]; then
        local line
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            eval "$line" >/dev/null 2>&1 || true
        done < <(tac "$JOURNAL")
        rm -rf "$STATE_DIR"
    fi
    flock -u 9
    exec 9>&-
}

# ---------------------------------------------------- privileged helpers ----

set_sysctl() { # set_sysctl key value  (key in slash form: net/ipv4/ip_forward)
    local key=$1 val=$2 old
    old=$(sysctl -n "$key" 2>/dev/null) || { warn "sysctl $key not available"; return 0; }
    [[ $old == "$val" ]] && return 0
    undo_push sysctl -qw "$key=$old"
    sysctl -qw "$key=$val"
}

have_iptables() {
    command -v iptables >/dev/null && iptables -w -S INPUT >/dev/null 2>&1
}

ipt_accept() { # ipt_accept CHAIN match... -> inserts "-j ACCEPT" at the top
    local chain=$1; shift
    local spec=("$@" -m comment --comment "$NAME" -j ACCEPT)
    undo_push iptables -w -D "$chain" "${spec[@]}"
    iptables -w -I "$chain" 1 "${spec[@]}"
}

# ---------------------------------------------------------- IPv4 helpers ----

ip2int() {
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

valid_ip() {
    local IFS=. o
    [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for o in $1; do (( o <= 255 )) || return 1; done
}

cidr_overlap() { # cidr_overlap a.b.c.d/len e.f.g.h/len
    local n1=${1%/*} n2=${2%/*} l1=32 l2=32 l mask
    [[ $1 == */* ]] && l1=${1#*/}
    [[ $2 == */* ]] && l2=${2#*/}
    l=$(( l1 < l2 ? l1 : l2 ))
    mask=$(( l == 0 ? 0 : (0xFFFFFFFF << (32 - l)) & 0xFFFFFFFF ))
    (( ($(ip2int "$n1") & mask) == ($(ip2int "$n2") & mask) ))
}

# Prints the first existing route/address that overlaps with the given /24.
subnet_conflict() {
    local net=$1 p
    while read -r p; do
        [[ $p == */* ]] || p+=/32
        (( ${p#*/} >= 8 )) || continue        # ignore default / split-default routes
        if cidr_overlap "$net" "$p"; then echo "$p"; return 0; fi
    done < <(
        ip -4 -o route show table all 2>/dev/null |
            awk '{ if ($1 ~ /^[0-9]/) print $1; else if ($2 ~ /^[0-9]/) print $2 }'
        ip -4 -o addr show 2>/dev/null | awk '{print $4}'
    )
    return 1
}

# ----------------------------------------------------- interface helpers ----

iface_exists() { [[ -n $1 && -e /sys/class/net/$1 ]]; }
iface_index()  { cat "/sys/class/net/$1/ifindex" 2>/dev/null || true; }
iface_oper()   { cat "/sys/class/net/$1/operstate" 2>/dev/null || echo absent; }

iface_up() { # VPN tunnels often report operstate "unknown" - treat as up
    local st
    iface_exists "$1" || return 1
    ip -o link show dev "$1" 2>/dev/null | grep -q '[<,]UP[,>]' || return 1
    st=$(iface_oper "$1")
    [[ $st == up || $st == unknown ]]
}

default_route_dev() {
    ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1
}

is_ethernet() {
    local p=/sys/class/net/$1
    [[ -e $p/device && ! -e $p/wireless && ! -e $p/phy80211 ]] || return 1
    [[ $(cat "$p/type" 2>/dev/null) == 1 ]]
}

is_p2p() { ip -o link show dev "$1" 2>/dev/null | grep -qE 'POINTOPOINT|NOARP'; }

is_virtual() { [[ $1 =~ ^(lo|docker|br-|veth|virbr|vnet|lxc|lxd|vmnet|vboxnet|cni|flannel|podman) ]]; }

is_vpn_like() {
    local i=$1 t kind
    t=$(cat "/sys/class/net/$i/type" 2>/dev/null || true)
    [[ $t == 65534 || $t == 512 ]] && return 0          # tun / wireguard / amneziawg / ppp
    kind=$(ip -d -o link show dev "$i" 2>/dev/null || true)
    [[ $kind =~ (^|[[:space:]])(tun|tap|wireguard|amneziawg)([[:space:]]|$) ]] && return 0
    [[ $i =~ ^(tun|tap|wg|awg|amn|ppp|nordlynx|proton|mullvad|tailscale) ]]
}

nm_running() { command -v nmcli >/dev/null && nmcli -t general status >/dev/null 2>&1; }

nm_dev_state() { # e.g. "connected", "disconnected", "unavailable", "unmanaged"
    nmcli -g GENERAL.STATE device show "$1" 2>/dev/null | sed -n 's/^[0-9]* (\(.*\))$/\1/p'
}

nm_dev_conn() { nmcli -g GENERAL.CONNECTION device show "$1" 2>/dev/null || true; }

carrier() {
    local c
    c=$(cat "/sys/class/net/$1/carrier" 2>/dev/null) || { echo "unknown (link down)"; return; }
    [[ $c == 1 ]] && echo "cable connected" || echo "no cable"
}

# --------------------------------------------------------- interactive ----

pick_downstream() {
    local list=() i p n idx def_dev
    while :; do
        list=()
        for p in /sys/class/net/*; do
            i=${p##*/}
            is_ethernet "$i" && list+=("$i")
        done
        echo
        info "${B}Ethernet port connected to the router's WAN port${N}"
        if (( ${#list[@]} == 0 )); then
            warn "No Ethernet interfaces found. Plug in a USB-Ethernet adapter if the laptop has no port."
            ask idx "Press Enter to rescan, or type an interface name manually" ""
            if [[ -n $idx ]]; then iface_exists "$idx" && { DS=$idx; return; }; warn "no such interface"; fi
            continue
        fi
        def_dev=$(default_route_dev)
        n=0
        for i in "${list[@]}"; do
            n=$((n + 1))
            local drv note='' nm=''
            drv=$(basename "$(readlink -f "/sys/class/net/$i/device/driver" 2>/dev/null)" 2>/dev/null || echo '?')
            nm_running && nm=" NM: $(nm_dev_state "$i")"
            [[ $i == "$def_dev" ]] && note=" ${R}(carries this laptop's Internet - do not use)${N}"
            printf '  %d) %-16s %s  driver=%s  %s%s%s\n' "$n" "$i" "$(cat "/sys/class/net/$i/address")" \
                "$drv" "$(carrier "$i")" "$nm" "$note"
        done
        ask idx "Choose 1-$n (r = rescan)" 1
        [[ $idx == r ]] && continue
        if [[ $idx =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= n )); then
            DS=${list[idx - 1]}
            if [[ $DS == "$def_dev" ]]; then
                warn "$DS is the laptop's current Internet uplink."
                confirm "Use it anyway? (the laptop will lose this uplink)" || continue
            fi
            return
        fi
        warn "invalid choice"
    done
}

pick_vpn() {
    local list=() i p n idx def_dev
    while :; do
        list=()
        for p in /sys/class/net/*; do
            i=${p##*/}
            [[ $i == lo || $i == "$DS" ]] && continue
            is_vpn_like "$i" && iface_up "$i" && list+=("$i")
        done
        def_dev=$(default_route_dev)
        echo
        info "${B}VPN tunnel interface (the VPN must already be connected)${N}"
        n=0
        for i in "${list[@]}"; do
            n=$((n + 1))
            local addr note=''
            addr=$(ip -4 -o addr show dev "$i" 2>/dev/null | awk '{print $4}' | paste -sd, -)
            [[ $i == "$def_dev" ]] && note=" ${G}(laptop's Internet currently goes through it)${N}"
            printf '  %d) %-16s %s%s\n' "$n" "$i" "${addr:-no IPv4}" "$note"
        done
        (( n == 0 )) && warn "No active tunnel-like interfaces found. Connect the VPN first (e.g. AmneziaVPN)."
        echo "  r) rescan     m) enter an interface name manually"
        ask idx "Choose" "$( (( n > 0 )) && echo 1 || echo r)"
        case $idx in
            r) continue ;;
            m)
                ask idx "Interface name" ""
                if iface_exists "$idx" && [[ $idx != "$DS" ]]; then VPN=$idx; return; fi
                warn "no such interface (or it is the downstream port)" ;;
            *)
                if [[ $idx =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= n )); then VPN=${list[idx - 1]}; return; fi
                warn "invalid choice" ;;
        esac
    done
}

pick_vpn_gateway() {
    # Point-to-point tunnels (tun, wireguard, amneziawg) need no next hop.
    VPN_GW=
    if is_p2p "$VPN"; then return; fi
    VPN_GW=$(ip -4 route show dev "$VPN" 2>/dev/null |
        awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}')
    echo
    warn "$VPN is not a point-to-point interface; a next-hop gateway is needed."
    while :; do
        ask VPN_GW "Gateway on $VPN" "$VPN_GW"
        valid_ip "$VPN_GW" && return
        warn "invalid IPv4 address"
    done
}

pick_subnet() {
    local cand c conflict def=''
    for cand in 10.99.99.0/24 10.123.45.0/24 172.31.99.0/24 192.168.199.0/24 10.77.77.0/24; do
        subnet_conflict "$cand" >/dev/null || { def=$cand; break; }
    done
    echo
    info "${B}Private subnet for the laptop <-> router link${N}"
    echo "  The laptop takes .1, the router gets an address from .100-.199 via DHCP."
    echo "  It must differ from the router's own LAN subnet and from anything this laptop uses."
    while :; do
        ask c "Subnet (/24)" "$def"
        c=${c%/24}; c=${c%.0}; c+=.0/24
        valid_ip "${c%/24}" || { warn "invalid subnet"; continue; }
        if conflict=$(subnet_conflict "$c"); then
            warn "$c overlaps with existing route/address $conflict"
            confirm "Use it anyway?" || continue
        fi
        SUBNET=$c
        local base=${c%.0/24}
        GW_IP=$base.1 POOL_START=$base.100 POOL_END=$base.199
        return
    done
}

pick_dns() {
    local detected='' d
    if command -v resolvectl >/dev/null; then
        for d in $(resolvectl dns "$VPN" 2>/dev/null | sed 's/^[^:]*://'); do
            valid_ip "$d" && detected+="$d "
        done
    fi
    detected=${detected% }
    echo
    info "${B}Upstream DNS for clients${N} (queries are forced through $VPN)"
    [[ -n $detected ]] && echo "  DNS pushed by the VPN: $detected"
    while :; do
        ask DNS "DNS servers, space separated" "${detected:-1.1.1.1 9.9.9.9}"
        local bad=0
        for d in $DNS; do valid_ip "$d" || bad=1; done
        (( bad == 0 )) && [[ -n $DNS ]] && return
        warn "enter IPv4 addresses only"
    done
}

# Gateway of the original (non-VPN) uplink. VPN clients usually keep the old
# default route with a higher metric, or at least a host route to the VPN server.
isp_gw() {
    local gw
    [[ -n $ISP_GW_FIXED ]] && { echo "$ISP_GW_FIXED"; return; }
    gw=$(ip -4 route show default table main dev "$ISP" 2>/dev/null |
        awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}')
    if [[ -z $gw ]] && nm_running; then
        gw=$(nmcli -g IP4.GATEWAY device show "$ISP" 2>/dev/null || true)
    fi
    if [[ -z $gw ]]; then
        gw=$(ip -4 route show table main dev "$ISP" 2>/dev/null |
            awk '{for (i = 1; i < NF; i++) if ($i == "via") {print $(i + 1); exit}}')
    fi
    valid_ip "$gw" && echo "$gw"
    return 0
}

iface_kind() {
    local p=/sys/class/net/$1
    if [[ -e $p/wireless || -e $p/phy80211 ]]; then echo "Wi-Fi"
    elif [[ $1 == ww* || $(cat "$p/type" 2>/dev/null) == 512 ]]; then echo "mobile modem"
    elif [[ $(readlink -f "$p/device" 2>/dev/null) == */usb* ]]; then echo "USB network"
    else echo "wired"; fi
}

pick_split() {
    echo
    info "${B}Split routing for Russia${N}"
    echo "  Russian IP ranges and Russian domains (.ru .su .рф ... + popular RU services)"
    echo "  can go directly through your normal Internet connection instead of the VPN."
    if confirm "Enable direct routing for Russian sites?"; then SPLIT=1; else SPLIT=0; fi
}

pick_isp() {
    local list=() i p n idx def_dev def_n=1 gw
    while :; do
        list=()
        for p in /sys/class/net/*; do
            i=${p##*/}
            [[ $i == "$DS" || $i == "$VPN" ]] && continue
            is_virtual "$i" && continue
            is_vpn_like "$i" && [[ $(cat "$p/type") != 512 ]] && continue
            iface_up "$i" || continue
            [[ -n $(ip -4 -o addr show dev "$i" 2>/dev/null) ]] || continue
            list+=("$i")
        done
        # Preselect the non-VPN interface holding the best default route.
        def_dev=$(ip -4 route show default table main 2>/dev/null |
            awk '{m = 0; for (i = 1; i < NF; i++) if ($i == "metric") m = $(i + 1);
                  for (i = 1; i < NF; i++) if ($i == "dev") print m, $(i + 1)}' |
            sort -n | awk '{print $2}' | while read -r i; do
                [[ " ${list[*]} " == *" $i "* ]] && { echo "$i"; break; }; done || true)
        echo
        info "${B}Original Internet connection for direct (Russian) traffic${N}"
        n=0
        for i in "${list[@]}"; do
            n=$((n + 1))
            [[ $i == "$def_dev" ]] && def_n=$n
            ISP=$i ISP_GW_FIXED='' gw=$(isp_gw)
            is_p2p "$i" && gw=${gw:-point-to-point}
            printf '  %d) %-16s %-13s %-18s gateway: %s%s\n' "$n" "$i" "$(iface_kind "$i")" \
                "$(ip -4 -o addr show dev "$i" | awk '{print $4}' | head -n1)" "${gw:-${R}not found${N}}" \
                "$([[ $i == "$def_dev" ]] && echo " ${G}(default uplink)${N}")"
        done
        (( n == 0 )) && warn "No usable uplink interfaces found (Wi-Fi / modem / wired with an IPv4 address)."
        echo "  r) rescan"
        ask idx "Choose" "$( (( n > 0 )) && echo "$def_n" || echo r)"
        [[ $idx == r ]] && continue
        if [[ $idx =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= n )); then
            ISP=${list[idx - 1]} ISP_GW_FIXED=''
            if [[ -z $(isp_gw) ]] && ! is_p2p "$ISP"; then
                warn "Could not detect the gateway on $ISP."
                while :; do
                    ask ISP_GW_FIXED "Gateway on $ISP" ""
                    valid_ip "$ISP_GW_FIXED" && break
                    warn "invalid IPv4 address"
                done
            fi
            return
        fi
        warn "invalid choice"
    done
}

pick_direct_dns() {
    local detected='' d
    if command -v resolvectl >/dev/null; then
        for d in $(resolvectl dns "$ISP" 2>/dev/null | sed 's/^[^:]*://'); do
            valid_ip "$d" && detected+="$d "
        done
    fi
    detected=${detected% }
    echo
    info "${B}DNS for Russian domains${N} (queried directly through $ISP, so answers are geo-correct)"
    [[ -n $detected ]] && echo "  DNS of your ISP connection: $detected"
    echo "  Yandex DNS: 77.88.8.8 77.88.8.1"
    while :; do
        ask DIRECT_DNS "DNS servers, space separated" "${detected:-77.88.8.8 77.88.8.1}"
        local bad=0
        for d in $DIRECT_DNS; do valid_ip "$d" || bad=1; done
        (( bad == 0 )) && [[ -n $DIRECT_DNS ]] && return
        warn "enter IPv4 addresses only"
    done
}

read_list_file() { # strips comments/blank lines
    [[ -f $1 ]] || return 0
    sed 's/#.*//; s/[[:space:]]//g' "$1" | grep -v '^$' || true
}

normalize_domain() {
    local d=${1,,}
    if [[ $d == *[![:ascii:]]* ]]; then             # рф -> xn--p1ai
        if command -v idn2 >/dev/null; then d=$(idn2 "$d" 2>/dev/null) || return 0
        else d=$(python3 -c 'import sys; print(sys.argv[1].encode("idna").decode())' "$d" 2>/dev/null) || return 0
        fi
    fi
    d=${d#\*.}; d=${d#.}; d=${d%.}
    [[ $d =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]] && echo "$d"
    return 0
}

pick_direct_domains() {
    local extra d n raw=("${DEFAULT_DIRECT_DOMAINS[@]}")
    mapfile -t -O "${#raw[@]}" raw < <(read_list_file "$SELF_DIR/direct-domains.txt")
    echo
    info "${B}Domains routed directly${N} (each includes all its subdomains)"
    echo "  Built in: ${DEFAULT_DIRECT_DOMAINS[*]}"
    [[ -f $SELF_DIR/direct-domains.txt ]] && echo "  Plus $SELF_DIR/direct-domains.txt"
    ask extra "Additional domains, space separated (Enter = none)" ""
    for d in $extra; do raw+=("$d"); done
    DIRECT_DOMAINS=()
    for d in "${raw[@]}"; do
        n=$(normalize_domain "$d")
        if [[ -z $n ]]; then warn "ignoring invalid domain '$d'"; continue; fi
        [[ " ${DIRECT_DOMAINS[*]} " == *" $n "* ]] || DIRECT_DOMAINS+=("$n")
    done
}

# ----------------------------------------------------------------- setup ----

free_table() { # free_table [excluded table] -> prints a free routing table number
    local t
    for t in $(seq 7399 7499); do
        [[ $t == "${1:-}" ]] && continue
        [[ -z $(ip -4 route show table "$t" 2>/dev/null) ]] || continue
        ip -4 rule show 2>/dev/null | grep -qE "^$t:|lookup $t( |$)" && continue
        echo "$t"
        return
    done
    die "no free routing table found"
}

pick_tables() {
    RT=$(free_table)                        # everything from the router -> VPN
    (( SPLIT )) && RT_DIRECT=$(free_table "$RT")   # Russian destinations -> ISP
    return 0
}

vpn_route_present() { [[ $(ip -4 route show table "$RT" 2>/dev/null) == *"dev $VPN "* ]]; }

add_vpn_route() {
    iface_exists "$VPN" || return 1
    if [[ -n $VPN_GW ]]; then
        ip -4 route replace default via "$VPN_GW" dev "$VPN" metric 10 table "$RT" 2>/dev/null
    else
        ip -4 route replace default dev "$VPN" metric 10 table "$RT" 2>/dev/null
    fi
}

# What the direct table depends on; when it changes (DHCP renew, roaming,
# modem re-plugged) the table is rebuilt.
isp_signature() {
    printf '%s|%s|%s' "$(iface_index "$ISP")" "$(isp_gw)" \
        "$(ip -4 route show table main dev "$ISP" scope link 2>/dev/null | awk '{print $1}' | paste -sd, -)"
}

# Direct table: the uplink's on-link networks + default via its gateway. No
# blackhole here on purpose: if the uplink has no route, Russian traffic falls
# through to the VPN table instead of being dropped.
sync_direct_table() {
    local gw r
    ip -4 route flush table "$RT_DIRECT" 2>/dev/null || true
    iface_up "$ISP" || return 1
    while read -r r; do
        [[ -n $r ]] && { ip -4 route add "$r" dev "$ISP" table "$RT_DIRECT" 2>/dev/null || true; }
    done < <(ip -4 route show table main dev "$ISP" scope link 2>/dev/null | awk '{print $1}')
    gw=$(isp_gw)
    if [[ -n $gw ]]; then
        ip -4 route add default via "$gw" dev "$ISP" metric 10 table "$RT_DIRECT" 2>/dev/null
    elif is_p2p "$ISP"; then
        ip -4 route add default dev "$ISP" metric 10 table "$RT_DIRECT" 2>/dev/null
    else
        return 1
    fi
}

direct_route_present() { [[ $(ip -4 route show table "$RT_DIRECT" 2>/dev/null) == *"default "*"dev $ISP "* ]]; }

loosen_rp() { # loose reverse-path filter, so asymmetric replies are accepted
    local rp
    rp=$(sysctl -n "net/ipv4/conf/$1/rp_filter" 2>/dev/null) || return 0
    [[ $rp == 1 ]] && set_sysctl "net/ipv4/conf/$1/rp_filter" 2
    return 0
}

# Russian IPv4 ranges -> $STATE_DIR/ru.cidr (normalized, nested prefixes removed).
fetch_ru_cidrs() {
    local rawf=$STATE_DIR/ru.raw url n
    : >"$rawf"
    if command -v curl >/dev/null; then
        for url in "${RU_CIDR_URLS[@]}"; do
            info "Downloading Russian IP ranges from ${url%%\?*}"
            if curl -fsSL --max-time 30 "$url" -o "$rawf.dl" 2>/dev/null; then
                grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "$rawf.dl" >"$rawf" || true
                n=$(wc -l <"$rawf")
                (( n > 1000 )) && break
                warn "unexpected content ($n prefixes), trying next source"
                : >"$rawf"
            else
                warn "download failed"
            fi
        done
        rm -f "$rawf.dl"
    fi
    if [[ ! -s $rawf && -f $SELF_DIR/ru-cidrs.txt ]]; then
        info "Using offline list $SELF_DIR/ru-cidrs.txt"
        read_list_file "$SELF_DIR/ru-cidrs.txt" >"$rawf"
    fi
    [[ -s $rawf ]] || warn "No Russian IP list available - only domain-based direct routing will work."
    read_list_file "$SELF_DIR/direct-cidrs.txt" >>"$rawf"
    awk '
        {
            split($0, a, "/"); len = (a[2] == "" ? 32 : a[2]) + 0
            if (split(a[1], o, ".") != 4 || len < 8 || len > 32) next
            ip = 0
            for (i = 1; i <= 4; i++) { if (o[i] !~ /^[0-9]+$/ || o[i] > 255) next; ip = ip * 256 + o[i] }
            blk = 2 ^ (32 - len); ip = int(ip / blk) * blk
            printf "%.0f %.0f %d.%d.%d.%d/%d\n", ip, ip + blk - 1,
                int(ip / 16777216), int(ip / 65536) % 256, int(ip / 256) % 256, ip % 256, len
        }' "$rawf" | sort -k1,1n -k2,2nr |
        awk '$1 > last || NR == 1 { print $3; last = $2 }' >"$STATE_DIR/ru.cidr"
    rm -f "$rawf"
}

load_ru_cidrs() {
    RU_COUNT=0
    [[ -s $STATE_DIR/ru.cidr ]] || return 0
    awk -v t="$NAME" '
        { b = b (c++ ? ", " : "") $0 }
        c == 1000 { print "add element inet " t " ru_dst { " b " }"; b = ""; c = 0 }
        END { if (c) print "add element inet " t " ru_dst { " b " }" }' \
        "$STATE_DIR/ru.cidr" >"$STATE_DIR/ru.nft"
    if nft -f "$STATE_DIR/ru.nft"; then
        RU_COUNT=$(wc -l <"$STATE_DIR/ru.cidr")
    else
        warn "failed to load the Russian IP list into nftables - only domains will be routed directly"
    fi
    rm -f "$STATE_DIR/ru.nft"
}

write_dnsmasq_conf() {
    local conf=$STATE_DIR/dnsmasq.conf d s
    : >"$conf"
    (( SPLIT )) || return 0
    for d in "${DIRECT_DOMAINS[@]}"; do
        for s in $DIRECT_DNS; do echo "server=/$d/$s@$ISP"; done
        echo "nftset=/$d/4#inet#$NAME#ru_dns"
    done >>"$conf"
}

start_dnsmasq() {
    write_dnsmasq_conf
    local args=(
        --keep-in-foreground --conf-file="$STATE_DIR/dnsmasq.conf" --no-resolv --no-hosts
        --bind-interfaces --interface="$DS" --except-interface=lo --listen-address="$GW_IP"
        --dhcp-range="$POOL_START,$POOL_END,255.255.255.0,1h" --dhcp-authoritative
        --dhcp-leasefile="$STATE_DIR/leases"
        --dhcp-option=option:router,"$GW_IP" --dhcp-option=option:dns-server,"$GW_IP"
        --cache-size=1000 --log-facility=- --log-dhcp
    )
    local d
    for d in $DNS; do args+=(--server="$d@$VPN"); done
    : >>"$STATE_DIR/leases"
    dnsmasq "${args[@]}" >>"$LOG" 2>&1 </dev/null &
    echo $! >"$STATE_DIR/dnsmasq.pid"
    sleep 0.7
    if ! kill -0 "$(cat "$STATE_DIR/dnsmasq.pid")" 2>/dev/null; then
        tail -n 15 "$LOG" >&2 || true
        return 1
    fi
}

restart_dnsmasq() {
    kill_pidfile "$STATE_DIR/dnsmasq.pid"
    start_dnsmasq
}

apply_nft() {
    local sets='' pre='' fwd='' nat=''
    if (( SPLIT )); then
        # New connections from the router to Russian destinations get a conntrack
        # mark; every packet of such a connection then carries the fwmark that
        # selects the direct routing table. The mark sticks to the connection, so
        # it keeps its path for its whole life.
        sets="
    set ru_dst { type ipv4_addr; flags interval; }
    set ru_dns { type ipv4_addr; }
    counter fwd_direct { }"
        pre="
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname \"$DS\" ct state new ip daddr @ru_dst ct mark set $MARK
        iifname \"$DS\" ct state new ip daddr @ru_dns ct mark set $MARK
        iifname \"$DS\" ct mark $MARK meta mark set $MARK
    }"
        fwd="
        iifname \"$DS\" oifname \"$ISP\" meta mark $MARK ip saddr $SUBNET counter name \"fwd_direct\" accept
        iifname \"$ISP\" oifname \"$DS\" ct state established,related accept"
        nat="
        oifname \"$ISP\" ip saddr $SUBNET masquerade"
    fi
    undo_push nft delete table inet "$NAME"
    nft -f - <<EOF
table inet $NAME {
    counter fwd_out { }
    counter fwd_blocked { }
    counter in_blocked { }
$sets
$pre

    chain input {
        type filter hook input priority filter - 5; policy accept;
        iifname "$DS" ct state established,related accept
        iifname "$DS" udp dport 67 accept
        iifname "$DS" ip daddr $GW_IP udp dport 53 accept
        iifname "$DS" ip daddr $GW_IP tcp dport 53 accept
        iifname "$DS" icmp type echo-request accept
        iifname "$DS" counter name "in_blocked" drop
    }

    chain forward {
        type filter hook forward priority filter - 5; policy accept;
        iifname "$DS" meta nfproto ipv6 counter name "fwd_blocked" drop
        oifname "$DS" meta nfproto ipv6 drop
        iifname "$DS" oifname "$VPN" tcp flags syn tcp option maxseg size set rt mtu
        iifname "$VPN" oifname "$DS" tcp flags syn tcp option maxseg size set rt mtu
        iifname "$DS" oifname "$VPN" ip saddr $SUBNET counter name "fwd_out" accept
        iifname "$VPN" oifname "$DS" ct state established,related accept
$fwd
        iifname "$DS" counter name "fwd_blocked" drop
        oifname "$DS" drop
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$VPN" ip saddr $SUBNET masquerade
$nat
    }
}
EOF
}

apply_iptables() {
    # ufw and docker keep their own FORWARD/INPUT chains with DROP policies; an accept
    # in our nft table cannot override their drop, so punch matching holes there too.
    have_iptables || return 0
    ipt_accept FORWARD -i "$DS" -o "$VPN" -s "$SUBNET"
    ipt_accept FORWARD -i "$VPN" -o "$DS" -m conntrack --ctstate RELATED,ESTABLISHED
    if (( SPLIT )); then
        ipt_accept FORWARD -i "$DS" -o "$ISP" -s "$SUBNET" -m mark --mark "$MARK"
        ipt_accept FORWARD -i "$ISP" -o "$DS" -m conntrack --ctstate RELATED,ESTABLISHED
    fi
    ipt_accept INPUT -i "$DS" -p udp --dport 67
    ipt_accept INPUT -i "$DS" -d "$GW_IP" -p udp --dport 53
    ipt_accept INPUT -i "$DS" -d "$GW_IP" -p tcp --dport 53
    ipt_accept INPUT -i "$DS" -p icmp --icmp-type echo-request
}

add_rule() { # add_rule <ip rule selector/action...> - journaled
    undo_push ip -4 rule del "$@"
    ip -4 rule add "$@"
}

# dnsmasq's upstream sockets are bound to an interface (server=x@iface); make
# sure such DNS queries find a route through that interface.
add_dns_rules() { # add_dns_rules IFACE TABLE PRIORITY
    local proto
    for proto in udp tcp; do
        add_rule oif "$1" ipproto "$proto" dport 53 lookup "$2" priority "$3" 2>/dev/null ||
            { warn "kernel/iproute2 too old for 'ip rule ... dport', relying on main table for DNS via $1"; return 0; }
    done
}

setup() {
    mkdir -p "$STATE_DIR"
    chmod 755 "$STATE_DIR"
    : >"$JOURNAL"
    echo $$ >"$STATE_DIR/pid"

    # Watchdog: survives kill -9 of this script and reverts everything.
    setsid "$SELF" --guardian $$ </dev/null >/dev/null 2>&1 &

    (( SPLIT )) && fetch_ru_cidrs

    info "Taking $DS away from NetworkManager (runtime only)"
    if nm_running && [[ $(nm_dev_state "$DS") != unmanaged ]]; then
        undo_push nmcli device set "$DS" managed yes
        nmcli device set "$DS" managed no
        sleep 1
    else
        # Not managed by NM: remember its addresses to put them back.
        local a
        while read -r a; do
            [[ -n $a ]] && undo_push ip addr add "$a" dev "$DS"
        done < <(ip -4 -o addr show dev "$DS" | awk '{print $4}')
    fi
    ip -o link show dev "$DS" | grep -q '[<,]UP[,>]' || undo_push ip link set dev "$DS" down
    undo_push ip addr flush dev "$DS"
    ip addr flush dev "$DS"
    ip link set dev "$DS" up
    ip addr add "$GW_IP/24" dev "$DS"

    info "Kernel settings"
    set_sysctl net/ipv4/ip_forward 1
    set_sysctl "net/ipv6/conf/$DS/disable_ipv6" 1
    [[ $(sysctl -n net/ipv4/conf/all/rp_filter) == 1 ]] && set_sysctl net/ipv4/conf/all/rp_filter 2
    loosen_rp "$VPN"
    (( SPLIT )) && loosen_rp "$ISP"

    info "Firewall / NAT / kill switch"
    apply_nft
    apply_iptables
    if (( SPLIT )); then
        load_ru_cidrs
        ok "Russian IP ranges loaded: $RU_COUNT prefixes"
    fi

    info "Policy routing: everything from $DS -> $VPN only (table $RT)"
    undo_push ip -4 route flush table "$RT"
    ip -4 route add "$SUBNET" dev "$DS" table "$RT"
    ip -4 route add blackhole default metric 4000 table "$RT"   # VPN down => drop, never fall back
    add_vpn_route || warn "could not add route via $VPN (is it up?)"
    add_rule iif "$DS" lookup "$RT" priority "$RT"
    add_dns_rules "$VPN" "$RT" $((RT - 3))

    if (( SPLIT )); then
        info "Policy routing: Russian destinations from $DS -> $ISP (table $RT_DIRECT)"
        undo_push ip -4 route flush table "$RT_DIRECT"
        sync_direct_table || warn "no route via $ISP yet - Russian traffic uses the VPN until it appears"
        ISP_SIG=$(isp_signature)
        add_rule iif "$DS" fwmark "$MARK" lookup "$RT_DIRECT" priority $((RT - 1))
        add_dns_rules "$ISP" "$RT_DIRECT" $((RT - 2))
    fi

    info "Starting temporary DHCP/DNS server (dnsmasq) on $DS"
    undo_push kill_pidfile "$STATE_DIR/dnsmasq.pid"
    start_dnsmasq || die "dnsmasq failed to start (see messages above)"

    ok "VPN router is up"
}

# --------------------------------------------------------------- monitor ----

counter_of() { # prints "packets bytes"
    nft list counter inet "$NAME" "$1" 2>/dev/null |
        awk '/packets/ {for (i = 1; i < NF; i++) {if ($i == "packets") p = $(i + 1); if ($i == "bytes") b = $(i + 1)}}
             END {print p + 0, b + 0}'
}

human() {
    local b=$1
    if (( b >= 1073741824 )); then printf '%d.%02d GiB' $((b / 1073741824)) $((b % 1073741824 * 100 / 1073741824))
    elif (( b >= 1048576 )); then printf '%d.%01d MiB' $((b / 1048576)) $((b % 1048576 * 10 / 1048576))
    elif (( b >= 1024 )); then printf '%d KiB' $((b / 1024))
    else printf '%d B' "$b"; fi
}

draw_status() {
    local out blk dir vpn_state fwd leases now isp_state ndns
    read -r -a out <<<"$(counter_of fwd_out)"
    read -r -a blk <<<"$(counter_of fwd_blocked)"
    if iface_up "$VPN" && vpn_route_present; then
        vpn_state="${G}UP${N}"
        fwd="${G}ACTIVE${N} (clients -> $VPN)"
    else
        vpn_state="${R}$(iface_oper "$VPN")${N}"
        fwd="${R}BLOCKED${N} (kill switch: waiting for $VPN to come back)"
    fi
    now=$(date +%s)
    printf '\e[H\e[J'
    echo "${B}VPN router active${N}   $(date '+%H:%M:%S')   started $(( (now - START_TS) / 60 )) min ago"
    echo
    printf '  %-13s %s  %s/24  (%s)\n' "Downstream:" "$DS" "$GW_IP" "$(carrier "$DS")"
    printf '  %-13s %s  %s\n' "VPN:" "$VPN" "$vpn_state"
    printf '  %-13s %s\n' "Forwarding:" "$fwd"
    printf '  %-13s %s via %s\n' "Client DNS:" "$DNS" "$VPN"
    printf '  %-13s %s pkts, %s    blocked: %s pkts\n' "Sent via VPN:" "${out[0]}" "$(human "${out[1]}")" "${blk[0]}"
    if (( SPLIT )); then
        read -r -a dir <<<"$(counter_of fwd_direct)"
        if direct_route_present; then
            isp_state="${G}UP${N} via $(isp_gw || true)"
        else
            isp_state="${Y}no route${N} (Russian traffic falls back to $VPN)"
        fi
        ndns=$(nft list set inet "$NAME" ru_dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l || true)
        echo
        printf '  %-13s %s  %s\n' "Direct (RU):" "$ISP" "$isp_state"
        printf '  %-13s %s prefixes from IP list, %s IPs of %s RU domains (DNS %s)\n' "Matching:" \
            "$RU_COUNT" "$ndns" "${#DIRECT_DOMAINS[@]}" "$DIRECT_DNS"
        printf '  %-13s %s pkts, %s\n' "Sent direct:" "${dir[0]}" "$(human "${dir[1]}")"
    fi
    [[ -n $LAST_EVENT ]] && printf '  %-13s %s\n' "Last event:" "$LAST_EVENT"
    echo
    echo "  ${B}DHCP leases${N}"
    leases=$(awk -v now="$now" '{printf "    %-15s %s  %-20s expires in %d min\n", $3, $2, ($4 == "*" ? "-" : $4), ($1 - now) / 60}' \
        "$STATE_DIR/leases" 2>/dev/null || true)
    echo "${leases:-    (none yet - connect the router WAN port and set WAN to DHCP)}"
    echo
    echo "  ${B}Router WAN settings${N}: DHCP (automatic)"
    echo "    or static: IP $POOL_START  mask 255.255.255.0  gateway $GW_IP  DNS $GW_IP"
    echo "    The router's LAN subnet must NOT be $SUBNET. Disable IPv6 on the router if possible."
    echo
    echo "  ${B}[t]${N} test exit IPs   ${B}[l]${N} dnsmasq log   ${B}[q]${N}/Ctrl-C stop and revert everything"
}

test_exit_ip() {
    printf '\e[H\e[J'
    if ! command -v curl >/dev/null; then echo "curl is not installed"; else
        echo "Querying https://ifconfig.me ..."
        printf '  via %-12s (what clients get): %s\n' "$VPN" \
            "$(curl -4 -s --max-time 8 --interface "$VPN" https://ifconfig.me || echo 'FAILED')"
        if (( SPLIT )); then
            printf '  via %-12s (Russian sites):   %s\n' "$ISP" \
                "$(curl -4 -s --max-time 8 --interface "$ISP" https://ifconfig.me || echo 'FAILED')"
        fi
        printf '  laptop default route:          %s\n' \
            "$(curl -4 -s --max-time 8 https://ifconfig.me || echo 'FAILED')"
        echo
        echo "If the $VPN test works but clients have no Internet, check the VPN app's"
        echo "kill switch / 'allow LAN' settings - it may block forwarded traffic."
    fi
    echo; read -rsn1 -p "Press any key..." || sleep 3
}

show_log() {
    printf '\e[H\e[J'
    tail -n 30 "$LOG" 2>/dev/null || echo "(empty)"
    echo; read -rsn1 -p "Press any key..." || sleep 3
}

monitor() {
    local key idx last_idx rc sig isp_idx
    START_TS=$(date +%s) LAST_EVENT=
    last_idx=$(iface_index "$VPN")
    while :; do
        # Tunnel recreated (reconnect) => new ifindex: re-add route, re-bind DNS.
        idx=$(iface_index "$VPN")
        if [[ $idx != "$last_idx" ]]; then
            if [[ -n $idx ]]; then
                add_vpn_route || true
                loosen_rp "$VPN"
                restart_dnsmasq || true
                LAST_EVENT="$(date '+%H:%M:%S') $VPN came back, forwarding resumed"
            else
                LAST_EVENT="$(date '+%H:%M:%S') $VPN disappeared, client traffic blocked"
            fi
            last_idx=$idx
        elif [[ -n $idx ]] && ! vpn_route_present; then
            add_vpn_route && LAST_EVENT="$(date '+%H:%M:%S') route via $VPN restored" || true
        fi
        # Uplink changed (new gateway/address, Wi-Fi roam, modem re-plugged).
        if (( SPLIT )); then
            sig=$(isp_signature)
            if [[ $sig != "$ISP_SIG" ]] || { iface_up "$ISP" && ! direct_route_present; }; then
                isp_idx=$(iface_index "$ISP")
                if sync_direct_table; then
                    LAST_EVENT="$(date '+%H:%M:%S') direct route via $ISP updated"
                else
                    LAST_EVENT="$(date '+%H:%M:%S') no route via $ISP, Russian traffic uses $VPN"
                fi
                [[ -n $isp_idx ]] && loosen_rp "$ISP"
                [[ ${ISP_SIG%%|*} != "$isp_idx" && -n $isp_idx ]] && { restart_dnsmasq || true; }
                ISP_SIG=$sig
            fi
        fi
        if ! kill -0 "$(cat "$STATE_DIR/dnsmasq.pid" 2>/dev/null)" 2>/dev/null; then
            restart_dnsmasq && LAST_EVENT="$(date '+%H:%M:%S') dnsmasq restarted" || true
        fi

        draw_status
        key=
        if read -rsn1 -t 3 key; then
            case $key in
                q|Q) return ;;
                t|T) test_exit_ip ;;
                l|L) show_log ;;
            esac
        else
            rc=$?
            (( rc > 128 )) || sleep 3   # stdin closed (not a timeout)
        fi
    done
}

# ------------------------------------------------------------------ main ----

on_exit() {
    local rc=$?
    set +e                      # cleanup must run to the end even if the terminal is gone
    trap '' INT TERM HUP
    trap - EXIT ERR
    { [[ -t 1 ]] && printf '\e[?25h'; stty sane; } 2>/dev/null
    if [[ -f $JOURNAL ]]; then
        { echo; info "Reverting all changes..."; } 2>/dev/null
        run_cleanup
        ok "Everything restored." 2>/dev/null
    fi
    exit "$rc"
}

main() {
    case ${1:-} in
        --guardian)
            local pid=$2
            trap '' INT TERM HUP
            while kill -0 "$pid" 2>/dev/null; do sleep 1; done
            run_cleanup
            exit 0 ;;
        -h|--help)
            sed -n '2,/^$/p' "$SELF" | sed 's/^# \{0,1\}//'
            exit 0 ;;
    esac

    if (( EUID != 0 )); then
        exec sudo -- "$SELF" "$@"
    fi

    local tool
    for tool in ip nft sysctl dnsmasq flock setsid tac awk sed; do
        command -v "$tool" >/dev/null || die "'$tool' not found (dnsmasq: sudo apt install dnsmasq-base)"
    done

    if [[ -f $JOURNAL ]]; then
        local old
        old=$(cat "$STATE_DIR/pid" 2>/dev/null || true)
        if [[ -n $old ]] && kill -0 "$old" 2>/dev/null && [[ $old != "$$" ]] &&
            tr '\0' ' ' <"/proc/$old/cmdline" 2>/dev/null | grep -q "$(basename "$SELF")"; then
            die "another instance is running (pid $old)"
        fi
        warn "Leftovers from a previous run found - reverting them first."
        run_cleanup
        ok "Previous state restored."
    fi
    [[ ${1:-} == --cleanup ]] && { ok "Nothing (more) to clean up."; exit 0; }

    echo "${B}Temporary VPN router${N} - shares a running VPN with a device on the Ethernet port."
    echo "All changes are reverted on exit, Ctrl-C, crash or reboot."

    pick_downstream
    pick_vpn
    pick_vpn_gateway
    pick_subnet
    pick_dns
    pick_split
    if (( SPLIT )); then
        pick_isp
        pick_direct_dns
        pick_direct_domains
    fi
    pick_tables

    echo
    info "${B}Summary${N}"
    echo "  Ethernet to router : $DS  ($GW_IP/24, DHCP $POOL_START-$POOL_END)"
    echo "  VPN interface      : $VPN${VPN_GW:+ via $VPN_GW}"
    echo "  Client DNS         : $DNS (through $VPN)"
    if (( SPLIT )); then
        echo "  Direct (Russia)    : RU IP ranges + ${#DIRECT_DOMAINS[@]} domains -> $ISP${ISP_GW_FIXED:+ via $ISP_GW_FIXED}"
        echo "  RU domains DNS     : $DIRECT_DNS (through $ISP)"
        echo "  Kill switch        : everything else ONLY via $VPN; IPv6 blocked"
    else
        echo "  Kill switch        : clients can reach the Internet ONLY via $VPN; IPv6 blocked"
    fi
    nm_running && [[ $(nm_dev_state "$DS") == connected ]] &&
        warn "$DS is currently connected by NetworkManager ('$(nm_dev_conn "$DS")') - it will be disconnected while the script runs."
    confirm "Start?" || exit 0

    trap on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap 'warn "error at line $LINENO: $BASH_COMMAND"' ERR

    setup
    [[ -t 1 ]] && printf '\e[?25l'
    monitor
}

main "$@"
