#!/bin/bash

scripts=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export KERIGUARD_SCRIPT_DIR="${scripts}"
repo_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && cd .. &> /dev/null && pwd )
export KERIGUARD_SCHEMA_DIR="${repo_dir}/schema"