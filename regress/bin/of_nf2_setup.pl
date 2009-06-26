#!/usr/bin/perl -w

use Getopt::Long;
use Data::Dumper;

use OF::OFUtil;
use Test::TestLib;

my ($mapFile, $controller);

print "Calling of_nf2_setup.pl\n";
print Dumper(@ARGV) . "\n";

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

setup_NF2($controller, $emerg);
