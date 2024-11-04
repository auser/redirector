#!/usr/bin/env bash

USERNAME="guest"  
PASSWORD="guest"
HOST="localhost"
PORT="15672"

VHOST="%2F"
EXCHANGE_NAME="test_exchange"
QUEUE_NAME="test_queue"
ROUTING_KEY="test_routing_key"
MESSAGE_LIMIT=10

VERBOSE="false"

declare -A Colors=(
    [Color_Off]='\033[0m'
    [Black]='\033[0;30m'
    [Red]='\033[0;31m'
    [Green]='\033[0;32m'
    [Yellow]='\033[0;33m'
    [Blue]='\033[0;34m'
    [Purple]='\033[0;35m'
    [Cyan]='\033[0;36m'
    [White]='\033[0;37m'
    [BBlack]='\033[1;30m'
    [BRed]='\033[1;31m'
    [BGreen]='\033[1;32m'
    [BYellow]='\033[1;33m'
    [BBlue]='\033[1;34m'
    [BPurple]='\033[1;35m'
    [BCyan]='\033[1;36m'
    [BWhite]='\033[1;37m'
    [UBlack]='\033[4;30m'
    [URed]='\033[4;31m'
    [UGreen]='\033[4;32m'
    [UYellow]='\033[4;33m'
    [UBlue]='\033[4;34m'
    [UPurple]='\033[4;35m'
    [UCyan]='\033[4;36m'
    [UWhite]='\033[4;37m'
)

log() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${Colors[Blue]}[INFO]${Colors[Color_Off]} $1"
    fi
}

error() {
    echo -e "${Colors[Red]}[ERROR]${Colors[Color_Off]} $1" >&2
}

# Create vhost
create_vhost() {
    log "Creating vhost: $VHOST"
    curl -u $USERNAME:$PASSWORD -H "content-type:application/json" \
        -XPUT http://$HOST:$PORT/api/vhosts/$VHOST
}

# Create exchange
create_exchange() {
    log "Creating exchange: $EXCHANGE_NAME"
    curl -u $USERNAME:$PASSWORD -H "Content-Type: application/json" \
        -XPUT -d'{"type":"direct","durable":true}' \
        http://$HOST:$PORT/api/exchanges/$VHOST/$EXCHANGE_NAME
}

# Create queue
create_queue() {
    log "Creating queue: $QUEUE_NAME"
    curl -u $USERNAME:$PASSWORD -H "Content-Type: application/json" \
        -XPUT -d'{"durable":true}' \
        http://$HOST:$PORT/api/queues/$VHOST/$QUEUE_NAME
}

# Create binding between exchange and queue
create_binding() {
    log "Creating binding between exchange $EXCHANGE_NAME and queue $QUEUE_NAME with routing key $ROUTING_KEY"
    curl -u $USERNAME:$PASSWORD -H "Content-Type: application/json" \
        -XPOST -d"{\"routing_key\":\"$ROUTING_KEY\"}" \
        http://$HOST:$PORT/api/bindings/$VHOST/e/$EXCHANGE_NAME/q/$QUEUE_NAME
}

create_all() {
    create_vhost
    create_exchange
    create_queue
    create_binding
}

# [exchange] -> [queue]
# Publish message to exchange
publish_message() {
    local payload="$1"
    if [ -z "$payload" ]; then
        error "No payload provided"
        return 1
    fi
    
    log "Publishing message: $payload"
    
    OUTPUT=$(curl -s -u $USERNAME:$PASSWORD -H "Content-Type: application/json" \
        -XPOST -d"{
        \"properties\":{},
        \"routing_key\":\"$ROUTING_KEY\",
        \"payload\":\"$payload\",
        \"payload_encoding\":\"string\"
        }" \
        http://$HOST:$PORT/api/exchanges/$VHOST/$EXCHANGE_NAME/publish)

    if [ "$VERBOSE" = "true" ]; then
        log "Publish result: $OUTPUT"
    fi
}

# Stream from stdin and publish each line
stream_publish() {
    log "Starting stream publishing. Press Ctrl+C to stop."
    
    # Create infrastructure if it doesn't exist
    create_all
    
    while IFS= read -r line; do
        # Escape special characters for JSON
        escaped_line=$(echo "$line" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        publish_message "$escaped_line"
    done
}

# Get messages from queue
get_messages() {
    log "Getting messages from queue: $QUEUE_NAME"
    curl -u $USERNAME:$PASSWORD -H "Content-Type: application/json" \
        -XPOST -d'{
        "count":'$MESSAGE_LIMIT',
        "requeue":true,
        "encoding":"auto",
        "ackmode":"ack_requeue_true"
        }' \
        http://$HOST:$PORT/api/queues/$VHOST/$QUEUE_NAME/get
}

# List queues to verify message count
get_message_count() {
    log "Getting message count for queue: $QUEUE_NAME"
    curl -s -u $USERNAME:$PASSWORD -H "content-type:application/json" \
        -XGET http://$HOST:$PORT/api/queues/$VHOST
}

# Clean up resources
clean() {
    log "Cleaning up resources"
    log "Deleting queue: $QUEUE_NAME"
    curl -u $USERNAME:$PASSWORD -XDELETE http://$HOST:$PORT/api/queues/$VHOST/$QUEUE_NAME
    log "Deleting exchange: $EXCHANGE_NAME"
    curl -u $USERNAME:$PASSWORD -XDELETE http://$HOST:$PORT/api/exchanges/$VHOST/$EXCHANGE_NAME
}

reset() {
  clean
  create_all
}

parse_opts() {
    local opt
    while getopts "dv:e:q:r:p:m:u:w:f:" opt; do
        case ${opt} in
        d) VERBOSE="true" ;;
        v) VHOST="$OPTARG" ;;
        e) EXCHANGE_NAME="$OPTARG" ;;
        q) QUEUE_NAME="$OPTARG" ;;
        r) ROUTING_KEY="$OPTARG" ;;
        p) PAYLOAD="$OPTARG" ;;
        m) MESSAGE_LIMIT="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        w) PASSWORD="$OPTARG" ;;
        \?)
            echo "Invalid option: $OPTARG" 1>&2
            exit 1
            ;;
        esac
    done
}



help() {
    echo -e "${Colors[Green]}Usage: $(basename "$0") [options] <command>
Options:
    -d  Verbose mode
    -v  Vhost
    -e  Exchange name
    -q  Queue name
    -r  Routing key
    -p  Message payload (for publish_message command)
    -u  Username
    -w  Password
    -m  Message limit (for get_messages command)

Commands:
    ${Colors[Green]}create_vhost${Colors[Color_Off]}                Create a vhost
    ${Colors[Green]}create_exchange${Colors[Color_Off]}             Create an exchange
    ${Colors[Green]}create_queue${Colors[Color_Off]}                Create a queue
    ${Colors[Green]}create_binding${Colors[Color_Off]}              Create a binding between an exchange and a queue
    ${Colors[Green]}create_all${Colors[Color_Off]}                  Create a vhost, exchange, queue and binding
    ${Colors[Green]}publish_message${Colors[Color_Off]}             Publish a message to an exchange
    ${Colors[Green]}stream_publish${Colors[Color_Off]}              Read from stdin and publish each line
    ${Colors[Green]}get_messages${Colors[Color_Off]}                Get messages from a queue
    ${Colors[Green]}get_message_count${Colors[Color_Off]}           List queues to verify message count
    ${Colors[Green]}clean${Colors[Color_Off]}                       Clean up resources (delete queue and exchange)
    ${Colors[Green]}reset${Colors[Color_Off]}                       Reset the environment (delete queue, exchange and vhost)

Examples:
    # Stream from a log file:
    tail -f /var/log/file | $(basename "$0") -d stream_publish
    # E.g.
    tail -f /opt/StarNE/bridge/bin/logstariso.1103 | ./rb.sh stream_publish

    # Create infrastructure and publish a single message:
    $(basename "$0") -d create_all
    $(basename "$0") -d -p "test message" publish_message

    # Get messages from queue:
    $(basename "$0") -d get_messages
"
    exit 1
}

main() {
    parse_opts "$@"
    shift $((OPTIND - 1))
    if [ $# -eq 0 ]; then
        help
    fi

    case "$1" in
    create_vhost) create_vhost ;;
    create_exchange) create_exchange ;;
    create_queue) create_queue ;;
    create_binding) create_binding ;;
    create_all) create_all ;;
    publish_message) publish_message "$PAYLOAD" ;;
    stream_publish) stream_publish ;;
    get_messages) get_messages ;;
    get_message_count) get_message_count ;;
    clean) clean ;;
    *) help ;;
    esac
}

main "$@"