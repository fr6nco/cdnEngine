#!/usr/bin/env bash

cd /Users/thomas/Projects/dizp/cdnengine
ryu-manager --config-file ./config/config.conf --app-lists ./apps/l2Handler.py ./apps/cdnHandler.py --verbose