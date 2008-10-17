#!/usr/bin/perl -w

`/sbin/modprobe veth`;
for (my $i = 0; $i < 4; $i++) {
	`/sbin/ip link add type veth`;
}

for (my $i = 0; $i < 8; $i++) {
	`sudo /sbin/ifconfig veth$i 192.168.1$i.1 netmask 255.255.255.0`;
}
