#!/bin/bash


# Issue Interface credential to keriguard for main file
LOCAL_SAID=$(kli vc create --name admin --alias admin --registry-name admin --schema ECRYEV1yPd4vnYNMqFSbTzvoxfz9iFlRMRTquU2uCAbY --private --recipient keriguard --data @"${KERIGUARD_SCRIPT_DIR}/data/keriguard-interface-data.json" | awk 'END{print $1}')
kli vc list --name admin --alias admin --issued
kli ipex grant --name admin --alias admin --said "${LOCAL_SAID}" --recipient registrar

# Issue Interface credential to peer
REMOTE_SAID=$(kli vc create --name admin --alias admin --registry-name admin --schema ECRYEV1yPd4vnYNMqFSbTzvoxfz9iFlRMRTquU2uCAbY --private --recipient peer --data @"${KERIGUARD_SCRIPT_DIR}/data/keriguard-peer-interface-data.json" | awk 'END{print $1}')
kli vc list --name admin --alias admin --issued
kli ipex grant --name admin --alias admin --said "${REMOTE_SAID}" --recipient registrar

echo "[\"$LOCAL_SAID\", \"$REMOTE_SAID\"]" | jq -f ${KERIGUARD_SCRIPT_DIR}/data/keriguard-connection-edges.jq > /tmp/keriguard-conneciton-edges.json
CONNECTION_SAID=$(kli vc create --name admin --alias admin --registry-name admin --schema EFUl2WDAhhdvqba5GhSxWbSU7eUGx_ZtbRZHgkXBFR-R --private --recipient keriguard --data @"${KERIGUARD_SCRIPT_DIR}/data/keriguard-connection-data.json" --edges @/tmp/keriguard-conneciton-edges.json | awk 'END{print $1}')
kli vc list --name admin --alias admin --issued
kli ipex grant --name admin --alias admin --said "${CONNECTION_SAID}" --recipient registrar

