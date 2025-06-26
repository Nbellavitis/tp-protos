#!/bin/bash

{
  printf "\x05\x01\x02"
  sleep 1
  printf "\x01\x02ni\x01a"
  sleep 1
  printf " world!\n"
} | nc 127.0.0.1 1080