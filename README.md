# Passive Identification of BackScatter (pibs)

Read a pcap file and display potential backscatter traffic on standard output

This is very early stage and subject to change.

# Install dependencies

As there were some changes in libwiretap, at least the version 2.6.3-1 is required.

``` shell
apt-get install libwiretap-dev
apt-get install libhiredis-dev
apt-get install libwsutil-dev
apt-get install libpcap-dev
apt-get install libglib2.0-dev
make
```

# How to use pibs

`./pibs -r pcapfile.cap -b`

`./pibs -u e344c4fb-442e-45a6-92b9-d8e30aeef448 -z 127.0.0.1 -p 6379 -y 2`

Consumes the files from the worker queue and write potential backscatter on
standard output. The worker queue should include absolute filenames.
In the example the redis server server is listening on port 6379 on the interface 127.0.0.1.
The redis database 2 is used as specified with the -y option.
The string e344c4fb-442e-45a6-92b9-d8e30aeef448 is the uuid that must be inline with the
worker.

`pibs -r source.cap.gz -w backscatter.cap`

Read the file source.cap.gz, identify potential backscatter and store it in the
file backscatter.cap to be further analysed with other tools such as wireshark

`pibs -r pcapfile.cap -s`

Read the file source.cap, identify potential backscatter and display the
usage of the used internal hash table. Feature for debugging purpose.

`pibs -r pcapfile.cap -d`

Dump the internal data structures for debugging purposes from the processing
of the pcapfile.

`pibs -n`

Create fresh internal data structure as shared memory for multi processing
purposes. The segment id is displayed on standard output.

`pibs -n -i myinstance.shm`

Create a shared memory and store the segment identifier in the file
myinstance.shm

`pibs -r pcapfile.cap.gz -a -i instance.shm`

Read pcapfile.cap.gz identify potential backscatter and store it in the
shared memory segment with the identifier stored in the file instance.shm.
The previous states are taken into account.

`pibs -i instance.shm -a -s`

Display the usage of the internal hash table from the shared memory segment
specified in the file instance.shm. This command can be executed in parallel
while another pibs instance is filling it.
