#!/bin/bash

sn=main
base_path=$(pwd)

start_client="npm run start"
start_sign1="npm run start_sign 3000"
start_sign2="npm run start_sign 3001"
start_sign3="npm run start_sign 3002"
start_petitionOwner="npm run start_petitionOwner 4000"
start_issuer="npm run start_issuer 5000"
start_docker="sudo docker-compose up"

servers_build="npm run build"

# for git
tmux new-session -s "$sn" -n "git" -d

cd "$base_path/client"
tmux new-window -t "$sn:$1" -n "client" $start_client

cd "$base_path/servers/docker"
tmux new-window -t "$sn:$1" -n "docker" $start_docker


cd "$base_path/servers"
$servers_build
tmux new-window -t "$sn:$2" -n "sign3000" $start_sign1
tmux new-window -t "$sn:$3" -n "sign3001" $start_sign2
tmux new-window -t "$sn:$4" -n "sign3002" $start_sign3
tmux new-window -t "$sn:$5" -n "petitionOwner" $start_petitionOwner
tmux new-window -t "$sn:$6" -n "issuer" $start_issuer

# not required for the system, but useful for debug
cd "$base_path/.."

tmux new-window -t "$sn:$6" -n "pgadmin" "source pgadmin4/bin/activate && sudo python pgadmin4/lib/python2.7/site-packages/pgadmin4/pgAdmin4.py"

tmux select-window -t "$sn:1"
tmux -2 attach-session -t "$sn"
