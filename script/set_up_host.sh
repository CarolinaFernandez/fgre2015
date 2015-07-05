#!/bin/bash

# Arguments: host (for interface) and VLAN
host=$1
vlan=$2
# Variables
user=$(whoami)
current_pwd=$PWD
eth=eth1
ip=192.161.24.29

function parse_args
{
  if [[ $host = "controller" ]] || [[ $host = "sender" ]]; then
    eth=eth1
    ip=192.161.24.29
  elif [[ $host = "receiver" ]]; then
    eth=eth2
    ip=192.161.24.30
  else
    echo "Invalid format. Run as follows: ./set_up_host.sh {sender|receiver} <vlan>"
    exit 0
  fi
}

function update_configure
{
  # Update host and install required packages
  ifconfig eth0 mtu 1480
  apt-get update
  apt-get install vlan git vim -y
  # Prepare environment
  if [[ $user != "root" ]]; then
    echo "syntax on" > /home/$user/.vimrc
  fi
  echo "syntax on" > /root/.vimrc
}

function set_up_ifaces
{
  # Set up interfaces
  eth_up=$(ifconfig | grep -o $eth)
  if [ "$eth_up" != "$eth" ]; then
    ifconfig $eth up
  fi
  eth_up=$(ifconfig | grep -o $eth | grep -o $vlan)
  if [ "$eth_up" != "$eth.$vlan" ]; then
    vconfig add $eth $vlan
    ifconfig $eth.$vlan up
  fi
  ip_up=$(ifconfig | grep -o $ip)
  if [ "$ip_up" != "$ip" ]; then
    ifconfig $eth.$vlan $ip
  fi
}

parse_args
if [[ $user != "root" ]]; then
  sudo -i || true
fi
cd $current_pwd
update_configure
set_up_ifaces
