# dpdk-apps

To build
```
# cd examples/echo
# make    ## will look for sources in ~
```

Use example
```
## enable hugepages
# echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# ./build/echo -- -p 0x3
```
