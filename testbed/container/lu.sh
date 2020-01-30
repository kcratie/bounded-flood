#!/bin/bash

function iping
{
  ping -c1 $1 > /dev/null
  #ping -c10 -nq $1 | tee -a /var/ipop-vpn/pre-ping-results.log
  #iperf -c $1 -e -yC -n200M | tee -a /var/ipop-vpn/pre-iperf-results.log
  iperf -c $1 -e -yC -n3G | tee -a /var/ipop-vpn/post-iperf-results.log
  ping -c10 -nq $1 | tee -a /var/ipop-vpn/post-ping-results.log
}

function run_docker_isntance
{
  docker exec ipop-dkr$1 /var/ipop-vpn/lu.sh iping $3
  #./lu.sh iping $2
  return $?
}

function run_host_instance
{
  while read ips
  do
    run_docker_isntance $ips
    if [ "$?" -ne "0" ]; then
      echo "Failure running docker_instance $ips"
    fi
  done < $1
}

case $1 in
  rhi)
    run_host_instance $2
    ;;
  iping)
    iping $2
    ;;
  *)
    echo "no match on input -> $1"
    ;;
esac
