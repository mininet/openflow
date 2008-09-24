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

# disable OF module
`snmpset -v2c -c public 10.9.8.9 iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.5.9.0 i 2`

