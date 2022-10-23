#!/usr/bin/env bash

set -e -o pipefail

function log() {
    FG_RESET='\033[0m'
    FG_RED='\033[1;31m' # bold red
    FG_GREEN='\033[0;32m'
    FG_YELLOW='\033[0;33m'
    FG_GREY='\033[1;37m'
    local msg
    msg="$(date +"%Y-%m-%dT%H:%M:%S%z") $*"
    case "$1" in
    ERROR)
        msg="$FG_RED$msg$FG_RESET"
        ;;
    SUCCESS)
        msg="$FG_GREEN$msg$FG_RESET"
        ;;
    WARN)
        msg="$FG_YELLOW$msg$FG_RESET"
        ;;
    *)
        msg="$FG_GREY$msg$FG_RESET"
        ;;
    esac
    echo -e "$msg" >&2
}

RUN_ID=$(head -c 32 /dev/random | sha1sum | cut -f1 -d' ')

log "Starting k8s-acme-chore
----------------------------
GitCommit: $GIT_COMMIT_SHA
BuildTimestamp: $BUILD_TIMESTAMP
RunId: $RUN_ID
WorkDir: $(pwd)
User: $(id)
Env: $(env | xargs echo)
acme.sh: $(acme.sh --version | tr '\n' '\t')
kubectl: $(kubectl version --client 2>/dev/null | tr '\n' '\t')
----------------------------"

[[ -z $ACCOUNT_EMAIL ]] && log ERROR "missing ACCOUNT_EMAIL" && exit 3
[[ -z $DOMAINS ]] && log ERROR "missing DOMAINS" && exit 3
[[ -z $TLS_SECRET ]] && log ERROR "missing TLS_SECRET" && exit 3

NAMESPACE="${NAMESPACE:-""}"
CONFIG_MAP="${CONFIG_MAP:-"acme-chore-config"}"
UPDATE_BEFORE_DAYS="${UPDATE_BEFORE_DAYS:-"14"}"
CHECK_INTERVAL="${CHECK_INTERVAL:-"6h"}"
DATA_DIR="${DATA_DIR:-/data}"
CA_SERVER="${CA_SERVER:-letsencrypt_test}"
HTTP_SCHEME=${HTTP_SCHEME:-http}
DEBUG=${DEBUG:-0}
KUBECTL_CONTEXT=${KUBECTL_CONTEXT:-""}
FORCE_RENEW=${FORCE_RENEW:-"false"}
VALID_TO=${VALID_TO:-""}
KEY_LENGTH=${KEY_LENGTH:-""}
HTTPS_INSECURE=${HTTPS_INSECURE:-""}

if [[ $HTTP_SCHEME == "https" ]]; then
    PORT="44380"
else
    PORT="44380"
fi

IFS=$',:\n \t|' read -r -a DOMAINS <<<"$DOMAINS"

if [[ $DEBUG == "true" ]]; then
    DEBUG="1"
fi
DEBUG=$((DEBUG * 1))

if [[ ! -d $DATA_DIR ]]; then
    log "Creating data directory: $DATA_DIR"
    mkdir -p "$DATA_DIR"
fi

SUPPORTED_CA_SERVERS=(letsencrypt zerossl buypass letsencrypt_test buypass_test)
[[ ! " ${SUPPORTED_CA_SERVERS[*]} " =~ ' '$CA_SERVER' ' ]] && log ERROR "Unsupported CA_SERVER $CA_SERVER. Should be one of $(
    IFS=,
    echo "${SUPPORTED_CA_SERVERS[*]}"
)" && exit 3

IS_REGISTERED=false

KUBECTL_ARGS=()
[[ -n $NAMESPACE ]] && KUBECTL_ARGS+=("--namespace" "$NAMESPACE")
[[ -n $KUBECTL_CONTEXT && $KUBECTL_CONTEXT != none ]] && KUBECTL_ARGS+=("--context" "$KUBECTL_CONTEXT")
[[ $KUBECONFIG == none ]] && unset KUBECONFIG

function check_certificate_is_good() {
    if ! pem=$(get_certificate_from_secret); then
        return 2
    fi

    log "Checking state of certificate: $(openssl x509 -noout -subject -issuer -startdate -enddate -fingerprint -ext subjectAltName <<<"$pem" | tr '\n' ' ')"

    local issuer subject ca
    issuer=$(openssl x509 -noout -issuer <<<"$pem")
    issuer=${issuer/"issuer="/}
    subject=$(openssl x509 -noout -subject <<<"$pem")
    subject=${subject/"subject="/}
    case "$issuer" in
    "$subject")
        log WARN "Certificate is self-signed"
        return 1
        ;;
    *O\ =\ \(STAGING\)\ Let\'s\ Encrypt*)
        ca=letsencrypt_test
        ;;
    *O\ =\ Let\'s\ Encrypt*)
        ca=letsencrypt
        ;;
    *O\ =\ ZeroSSL*)
        ca=zerossl
        ;;
    *CN\ =\ Buypass\ *Test*)
        ca=buypass_test
        ;;
    *CN\ =\ Buypass\ *)
        ca=buypass
        ;;
    *)
        ca=$issuer
        ;;
    esac

    if [[ $CA_SERVER != "$ca" ]]; then
        log WARN "Certificate is issued by '$ca' but expected is '$CA_SERVER'"
        return 1
    else
        log "Certificate is issued by expected CA '$ca'"
    fi

    local now
    now=$(date +"%s")

    # check start date
    local start_date_field start_epoch
    start_date_field=$(openssl x509 -noout -startdate <<<"$pem")
    start_epoch=$(date --date="${start_date_field/"notBefore="/}" --utc +"%s")
    if ((start_epoch > now)); then
        log WARN "Certificate is not valid yet | $start_date_field"
        return 1
    fi

    # check end date
    local end_date_field end_epoch expires_in_days
    end_date_field=$(openssl x509 -noout -enddate <<<"$pem")
    end_epoch=$(date --date="${end_date_field/"notAfter="/}" --utc +"%s")
    expires_in_days=$(((end_epoch - now) / 60 / 60 / 24))
    if ((end_epoch < now)); then
        log WARN "Certificate is already expired | $end_date_field"
        return 1
    elif ((expires_in_days < UPDATE_BEFORE_DAYS)); then
        log WARN "Certificate expires in $expires_in_days days | $end_date_field | But UPDATE_BEFORE_DAYS is set to $UPDATE_BEFORE_DAYS days"
        return 1
    else
        log "Certificate has $expires_in_days days remaining | $end_date_field"
        return 0
    fi

}

function load_ca_config() {
    log "Loading configuration from configMap: $CONFIG_MAP "
    ca_gz_b64=$(kubectl "${KUBECTL_ARGS[@]}" get configmaps "$CONFIG_MAP" --output jsonpath='{.binaryData.ca_tgz}' --ignore-not-found)
    if [[ -z $ca_gz_b64 ]]; then
        log WARN "ConfigMap $CONFIG_MAP does not exist or doesn't have data"
        return
    fi
    log "Unarchiving contents to configuration directory '$DATA_DIR/ca'"
    base64 -d <<<"$ca_gz_b64" | tar -xzv -C "$DATA_DIR"
}

function store_ca_config() {
    local ca_config_dir="ca"
    log "Archiving ca configuration directory '$ca_config_dir' from $DATA_DIR  to /tmp/ca.tgz"
    tar -czv -f "/tmp/ca.tgz" -C "$DATA_DIR" "$ca_config_dir"
    log "Storing configuration to configMap: $CONFIG_MAP"
    kubectl "${KUBECTL_ARGS[@]}" create configmap "$CONFIG_MAP" --save-config --dry-run=client --from-file="ca_tgz=/tmp/ca.tgz" -o yaml | kubectl "${KUBECTL_ARGS[@]}" apply -f -
}

function get_certificate_from_secret() {
    local pem
    log "Fetching tls secret from Kubernetes SECRET=$NAMESPACE/$TLS_SECRET | cli args: ${KUBECTL_ARGS[*]} KubeConfig:$KUBECONFIG"
    kubectl "${KUBECTL_ARGS[@]}" get secrets "$TLS_SECRET" --output jsonpath="{.data['tls\.crt']}" | base64 -d
}

function update_secret() {
    log "Updating TLS secret $TLS_SECRET using  cert=$1 key=$2"
    kubectl "${KUBECTL_ARGS[@]}" create secret tls "$TLS_SECRET" --save-config --dry-run=client --cert="$1" --key="$2" -o yaml | kubectl "${KUBECTL_ARGS[@]}" apply -f -
}

function http_server() {
    case "$1" in
    start)
        if kill -n 0 "$SERVER_PID" 2>/dev/null; then
            log WARN "http server is already running as pid: $SERVER_PID"
            return
        fi
        log "Starting http server at port $PORT"
        local www_dir="$DATA_DIR/www"
        mkdir -p "$www_dir/.well-known/acme-challenge"
        echo "$RUN_ID" >"$www_dir/.well-known/acme-challenge/__check"
        # local tmp_file="/tmp/_acme_chore_server_response"
        # echo -en "HTTP/1.0 200 OK\nContent-Length: ${#RUN_ID}\n\n$RUN_ID" >$tmp_file
        # socat -dd -T 5 TCP-LISTEN:$PORT,crlf,reuseaddr,fork SYSTEM:"cat $tmp_file" &
        if command -v thttpd >/dev/null; then
            http_cmd="thttpd -d $www_dir -p $PORT -D"
        elif command -v mini_httpd >/dev/null; then
            http_cmd="mini_httpd -d $www_dir"
        elif command -v darkhttpd >/dev/null; then
            http_cmd="darkhttpd $www_dir --port PORT"
        else
            log ERROR "No http server commands found!"
            return 2
        fi
        log "http server command: $http_cmd"
        eval "$http_cmd &"
        SERVER_PID=$!
        sleep 1s
        if kill -n 0 "$SERVER_PID" 2>/dev/null; then
            log SUCCESS "http server is started (pid:$SERVER_PID)"
        else
            log ERROR "http server is failed to start (pid:$SERVER_PID)"
        fi
        ;;
    stop)
        if ! kill -n 0 "$SERVER_PID" 2>/dev/null; then
            log WARN "http server is not running with (pid:$SERVER_PID)"
            return
        fi
        log "Stopping http server (pid:$SERVER_PID)"
        kill -s SIGTERM "$SERVER_PID"
        wait "$SERVER_PID" || return 0
        ;;
    *)
        return 2
        ;;
    esac
}

function test_http01_challenge_endpoints {
    local endpoint resp domain
    for domain in "${DOMAINS[@]}"; do
        endpoint="$HTTP_SCHEME://$domain/.well-known/acme-challenge/__check"
        # endpoint=localhost:$PORT
        log "[$domain] Checking if ACME http01 challenge endpoint reachable ($endpoint)"
        resp=$(curl -sS -L -k -m 10 -w " | Status: %{http_code}\n" "$endpoint")
        if [[ $resp =~ $RUN_ID ]]; then
            log SUCCESS "[$domain] Endpoint test passed"
            continue
        else
            log ERROR "[$domain] Endpoint test failed.  Got response: $resp"
            return 1
        fi
    done
}

function do_acme() {
    local args=()
    if [[ $DEBUG != 0 ]]; then
        args+=("--debug" "$DEBUG")
    fi
    if [[ $IS_REGISTERED != true ]]; then
        log "Try registering account for CA $CA_SERVER with email $ACCOUNT_EMAIL"
        acme.sh --home "$DATA_DIR" --register-account --server "$CA_SERVER" -m "$ACCOUNT_EMAIL" --log-level 2
        IS_REGISTERED=true
        store_ca_config
    fi

    if [[ $FORCE_RENEW == true || $FORCE_RENEW == 1 || $FORCE_RENEW == now ]]; then
        args+=("--force")
    fi

    # args+=("--standalone")
    args+=("--webroot" "$DATA_DIR/www")

    if [[ $HTTP_SCHEME == "https" ]]; then
        args+=("--alpn" "--tlsport" "$PORT")
    else
        args+=("--httpport" "$PORT")
    fi
    if [[ -n $VALID_TO ]]; then
        args+=("--valid-to" "$VALID_TO")
    fi
    if [[ -n $KEY_LENGTH ]]; then
        args+=("--keylength" "$KEY_LENGTH")
    fi
    if [[ $HTTPS_INSECURE == true || $HTTPS_INSECURE == 1 ]]; then
        args+=("--insecure")
    fi
    for d in "${DOMAINS[@]}"; do
        args+=("-d" "$d")
    done
    acme.sh --home "$DATA_DIR" --issue --server "$CA_SERVER" "${args[@]}" --log-level 2 --renew-hook "echo 'It is a renew'"
    EC=$? # https://github.com/acmesh-official/acme.sh/wiki/Exit-Codes
    if [[ $EC == 2 ]]; then
        log SUCCESS "ACME exchange is finished without updating certificate"
        return 0
    fi
    if [[ $EC -eq 0 ]]; then
        local crt_file="$DATA_DIR/${DOMAINS[0]}/${DOMAINS[0]}.cer"
        local key_file="$DATA_DIR/${DOMAINS[0]}/${DOMAINS[0]}.key"
        log SUCCESS "ACME exchange is success. | Certificate: $(openssl x509 -noout -subject -issuer -startdate -enddate -fingerprint -ext subjectAltName <"$crt_file" | tr '\n' ' ')"
        update_secret "$crt_file" "$key_file"
        EC=$?
    fi
    return $EC
}

# -----------------------

log "Domains=${DOMAINS[*]/ /|} Email=$EMAIL Secret=$NAMESPACE/$TLS_SECRET CAServer=$CA_SERVER CheckInterval=$CHECK_INTERVAL UpdateBeforeDays=$UPDATE_BEFORE_DAYS HttpScheme=$HTTP_SCHEME Port=$PORT"

trap 'echo "[exit handler]" && jobs %% 2>/dev/null && echo "Killing background tasks..." && kill -s SIGTERM $(jobs -p) && wait' EXIT

load_ca_config

while true; do
    http_server start
    if ! test_http01_challenge_endpoints; then
        retry=10s
        log ERROR "ACME http01 challenge endpoints test failed! Did you configure Ingress rule? Did you update DNS record?  Will retry after $retry"
        sleep $retry
        continue
    else
        log SUCCESS "All ACME http01 challenge endpoints are reachable"
    fi

    if check_certificate_is_good && [[ $FORCE_RENEW != now ]]; then
        log SUCCESS "Certificate is good. Nothing to do"
    else
        case "$?" in
        1)
            log "Renewing certificate | FORCE_RENEW=$FORCE_RENEW"
            do_acme || log "ERROR: do_acme() failed with EC=$?"
            ;;
        *)
            log ERROR "Failed to check certificate state. EC=$?"
            ;;
        esac
    fi

    http_server stop
    log "Next check is after $CHECK_INTERVAL"
    sleep "$CHECK_INTERVAL"
done
