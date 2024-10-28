#!/usr/bin/env bash

DIR_PATH=$(realpath $(dirname "$0"))
source $DIR_PATH/colors.sh
CONTAINER_NAME="redirector-dev"

debug() {
  if [ $VERBOSE == "true" ]; then
    printf "${Colors[BBlack]}%s" echo -e "$1"
  fi
}

docker_instance() {
  docker ps | grep "$CONTAINER_NAME" | awk '{print $1}'
}

exec_instance() {
    local docker_instance=$(docker_instance)
    if [[ -z "$docker_instance" ]]; then
        printf "${Colors[BRed]}No container found${Colors[Color_Off]}"
        exit 1
    fi
    docker exec -it ${docker_instance} /usr/bin/zsh
}


parse_opts() {
  local opt
  while getopts "v" opt; do
    case ${opt} in
    v) VERBOSE="true" ;;
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
  -v  Verbose mode

Commands:
  ${Colors[Green]}exec${Colors[Color_Off]}                Execute a command in the docker container
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
  exec) exec_instance ;;
  *) help ;;
  esac
}

main "$@"