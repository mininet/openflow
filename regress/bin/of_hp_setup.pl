#!/usr/bin/perl -w

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;

my $mapFile;

# Process command line options
unless ( GetOptions( "map=s" => \$mapFile, ) ) {
	print "unrecognized option\n";
	exit 1;
}

if ( defined($mapFile) ) {
	nftest_process_iface_map($mapFile);
}

setup_pcap_interfaces();

# set OF VLAN to 18
`snmpset -v2c -c public 10.9.8.9 iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.5.10.0 i 18`;

# set controller string
`snmpset -v2c -c public 10.9.8.9 iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.5.11.0 s tcp:10.9.8.4:975`;

# enable OF module
`snmpset -v2c -c public 10.9.8.9 iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.5.9.0 i 1`

