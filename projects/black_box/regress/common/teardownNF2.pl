#!/usr/bin/perl -w

use Getopt::Long;

use Test::TestLib;
use OF::OFUtil;

my $mapFile;
# Process command line options
unless ( GetOptions ("map=s" => \$mapFile,)) { 
	usage(); 
	exit 1;
}

if (defined($mapFile)) {
        nftest_process_iface_map($mapFile);
}

teardown_kmod("true");

exit(0);
