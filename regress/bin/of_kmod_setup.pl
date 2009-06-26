#!/usr/bin/perl -w

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;

my $mapFile, $controller;

# Process command line options
unless ( GetOptions( "map=s" => \$mapFile,
                     "emerg" => \$emerg,
                     "controller=s", \$controller) ) {
	print "unrecognized option\n";
	exit 1;
}

if ( defined($mapFile) ) {
	nftest_process_iface_map($mapFile);
}

setup_kmod($controller, $emerg);
