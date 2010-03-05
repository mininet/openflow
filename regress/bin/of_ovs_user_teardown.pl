#!/usr/bin/perl -w
# Jean Tourrilhes - HP-Labs

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;

my $mapFile;

# Process command line options
unless ( GetOptions( "map=s" => \$mapFile, ) ) {
	print "unrecognized option\n";
	exit 1;
}

# If not specified on command line, use enviroment variable.
# Try specific first, then try generic - Jean II
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_OVS_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_OVS_MAP_ETH}";
}
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_MAP_ETH}";
}

if ( defined($mapFile) ) {
	nftest_process_iface_map($mapFile);
} 

# Get the directly where Open vSwitch resides
my $ovs_dir = $ENV{'OFT_OVS_ROOT'};

# Just kill ovs-openflowd
`killall ovs-openflowd`;
