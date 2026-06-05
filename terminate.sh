#!/usr/bin/env sh
TEST_PIDS=$(ps aux | grep python | grep -E "main" | awk {'print $2'})
if [ "$TEST_PIDS" != "" ]; then
    kill -9 $TEST_PIDS
fi

if [ -f ~/.simulaqron_pids/simulaqron_network_default.pid ]; then
    if ! simulaqron stop; then
        cat $HOME/.simulaqron_pids/simulaqron_network_default.pid | xargs kill -9
    fi
fi
