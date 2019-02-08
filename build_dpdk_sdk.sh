#!/bin/bash

apt-get -y install gcc libnuma-dev make python
## download dpdk SDK
wget http://fast.dpdk.org/rel/dpdk-18.08.tar.gz
tar zvxf dpdk-18.08.tar.gz

## export build vars
cd dpdk-18.08
export RTE_SDK=`pwd`

## build dpdk
NUM_CPUS=$(cat /proc/cpuinfo | grep "processor\\s: " | wc -l)
#export RTE_TARGET=x86_64-native-linuxapp-gcc
make defconfig
make -j $NUM_CPUS

## build sample apps
#NUM_CPUS=$(cat /proc/cpuinfo | grep "processor\\s: " | wc -l)
#export RTE_TARGET=build
#make -C examples -j $NUM_CPUS
