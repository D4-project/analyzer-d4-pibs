# Passive Identification of BackScatter
Read a pcap file and display potential backscatter traffic on standard output

This is very early stage and subject to change.


# Install dependencies

As there were some changes in libwiretap, at least the version 2.6.3-1 is needed.
``` shell
apt-get install libwiretap-dev
apt-get install libhiredis-dev
apt-get install libwsutil-dev
make
```

# How to use

``` shell
./pibs -r pcapfile.cap -b
```


