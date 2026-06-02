#!/bin/bash


# Issue Interface credential to keriguard for main file
kg interface create --name admin --alias admin --registry-name admin --recipient keriguard --interface-name wg0 --listen-port 5000 --address "10.0.0.4/24" --interface-description "Main Interface Credential" --output keriguard-wg0.cesr
kli vc list --name admin --alias admin --issued
# Issue Interface credential to peer
kg interface create --name admin --alias admin --registry-name admin --recipient peer --interface-name wg0 --listen-port 5000 --address "10.0.0.3/24" --interface-description "Main Interface Credential" --output keriguard-peer-wg0.cesr

kli vc list --name admin --alias admin --issued

exit

kg peer add --name admin --alias admin --connection-name "Peer2Peer" --allowed-ips "10.0.51.1/32" --endpoint 147.182.240.249:43567 --local-interface-said ELyZc672lDbFDBb8U6icJv1367o50YAXJ_fjLK501azU --remote-interface-said EE8gGw4iRQntJD-GeW6Ud76oOKbqKWl7fzIuIOyUKFsf
kli vc list --name admin --alias admin --issued

