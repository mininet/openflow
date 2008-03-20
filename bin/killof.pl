#!/usr/bin/perl -w

use strict;

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

# check that we're root?
my $who = `whoami`;
if (trim($who) ne 'root') { die "must be root\n"; }

# check if openflow kernel module loaded
my $of_kmod_loaded = `lsmod | grep openflow_mod`;
if ($of_kmod_loaded eq "") { die "nothing to do, exiting\n"; } 

print "tearing down interfaces and datapaths\n";

# cleanup by deleting data paths, removing kmod, and killing controller
# should really make this smarter, but ah well
`dpctl delif 0 eth1`;
`dpctl delif 0 eth2`;
`dpctl delif 0 eth3`;
`dpctl delif 0 eth4`;
`dpctl deldp 0`;

my $of_kmod_removed = `rmmod openflow_mod`;
if ($of_kmod_removed eq "") {
	# didn't complain, we're ok
}
else {
	print "error: rmmod failed.  check killof.pl for errors.\n";
	print "$of_kmod_removed\n";
}

$of_kmod_loaded = `lsmod | grep openflow_mod`;
if ($of_kmod_loaded eq "") {
        print "successfully removed kernel module\n";
	exit 1;
}
else {
        print "failed to remove kernel module... please fix!\n";
        exit 1;
}
