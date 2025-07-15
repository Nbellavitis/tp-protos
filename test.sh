#!/bin/bash
for i in {1..500}; do
    curl -x socks5h://127.0.0.1:1080 http://www.google.com:81 --max-time 5 > /dev/null 2>&1 &
done

wait
