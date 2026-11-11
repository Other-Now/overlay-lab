#!/bin/bash
# Bring up an IKEv2 SA between a and b with strongSwan (charon + swanctl).
#   ike.sh up     start one charon per namespace, load config, initiate from a
#   ike.sh down   stop both
# Each charon runs in its own mount namespace with a private /run, so the two
# daemons don't fight over /run/charon.pid. The vici control socket is moved to
# $WORK so swanctl can reach it from outside.
source "$(dirname "$0")/lib.sh"

D="$WORK/ike"

conf_side() {  # $1 = side (a|b)  $2 = local underlay  $3 = remote underlay  $4 = local ts  $5 = remote ts
    local s=$1
    mkdir -p "$D/$s"
    cat >"$D/$s/strongswan.conf" <<EOF
charon {
    # Explicit plugin list: we do not rely on /etc/strongswan.d existing.
    load = random nonce openssl pem pkcs1 x509 revocation constraints pubkey kdf gcm aes sha2 hmac kernel-netlink socket-default vici
    plugins { vici { socket = unix://$D/$s/charon.vici } }
    install_routes = no
    filelog {
        log {
            path = $D/$s/charon.log
            default = 1
            ike = 2
            time_format = %H:%M:%S
        }
    }
}
swanctl { load = random nonce openssl pem pkcs1 x509 pubkey }
EOF
    cat >"$D/$s/swanctl.conf" <<EOF
connections {
    lab {
        version = 2
        local_addrs = $2
        remote_addrs = $3
        proposals = aes128gcm16-prfsha256-x25519
        local {
            auth = psk
            id = $s.lab
        }
        remote {
            auth = psk
            id = $( [[ $s == a ]] && echo b || echo a ).lab
        }
        children {
            lab {
                local_ts = $4/32
                remote_ts = $5/32
                mode = tunnel
                esp_proposals = aes128gcm16-x25519
            }
        }
    }
}
secrets {
    ike-lab {
        id-a = a.lab
        id-b = b.lab
        secret = "overlay-lab-not-a-real-secret"
    }
}
EOF
}

start_charon() {  # $1 = side
    local s=$1
    rm -f "$D/$s/charon.vici" "$D/$s/charon.log"
    ip netns exec $s env STRONGSWAN_CONF="$D/$s/strongswan.conf" \
        unshare --mount bash -c 'mount -t tmpfs none /run && exec /usr/lib/ipsec/charon' \
        >"$D/$s/charon.out" 2>&1 &
    for _ in $(seq 50); do [[ -S "$D/$s/charon.vici" ]] && return 0; sleep 0.1; done
    log "charon in $s did not start:"; cat "$D/$s/charon.out" >&2; return 1
}

sw() {  # $1 = side, $2 = swanctl command, rest = its options (--uri is per-command)
    local s=$1 cmd=$2; shift 2
    STRONGSWAN_CONF="$D/$s/strongswan.conf" swanctl "$cmd" --uri "unix://$D/$s/charon.vici" "$@"
}

case "${1:-}" in
up)
    conf_side a $A_UL $B_UL $A_SEC $B_SEC
    conf_side b $B_UL $A_UL $B_SEC $A_SEC
    start_charon a; start_charon b
    sw a --load-all --file "$D/a/swanctl.conf" >"$D/a/load.log" 2>&1
    sw b --load-all --file "$D/b/swanctl.conf" >"$D/b/load.log" 2>&1
    sw a --initiate --child lab --timeout 10 >"$D/initiate.log" 2>&1
    sw a --list-sas >"$D/sas.txt"
    ip -n a xfrm state >"$D/xfrm_state_a.txt"
    ;;
down)
    pkill -x charon 2>/dev/null || true
    ;;
*) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
