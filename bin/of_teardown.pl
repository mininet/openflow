#!/usr/bin/perl -w

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;

my $mapFile;
# Process command line options
unless ( GetOptions ("map=s" => \$mapFile,)) { 
	usage(); 
	exit 1;
}

if (defined($mapFile)) {
        nftest_process_iface_map($mapFile);
}

my $isNF2 = shift;

teardown_kmod($isNF2);

exit(0);
