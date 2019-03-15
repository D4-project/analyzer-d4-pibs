# Passive Identification of BackScatter
Read a pcap file and display potential backscatter traffic on standard output

This is very early stage and subject to change.


# Install dependencies

As there were some changes in libwiretap, at least the version 2.6.3-1 is needed.
``` shell
apt-get install libwiretap-dev
apt-get install libhiredis-dev
apt-get install libwsutil-dev
apt-get install libpcap-dev
apt-get install libglib2.0-dev
make
```

# How to use

``` shell
./pibs -r pcapfile.cap -b

./pibs -u e344c4fb-442e-45a6-92b9-d8e30aeef448 -z 127.0.0.1 -p 6379

Consumes the files from the worker queue and write potential backscatter on
standard output. The worker queue should include absolute filenames.
In the example the redis server server is listening on port 6379 on the interface 127.0.0.1.
The string e344c4fb-442e-45a6-92b9-d8e30aeef448 is the uuid that must be inline with the
worker.
```


