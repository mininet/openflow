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

# Start by killing secchan or ovs-openflowd
`killall secchan`;
`killall ovs-openflowd`;

# check if openflow kernel module loaded
my $of_kmod_loaded = `lsmod | grep openvswitch_mod`;
if ( $of_kmod_loaded eq "" ) { exit 0; }

print "tearing down interfaces and datapaths\n";

# remove interfaces from openflow
for ( my $i = 5 ; $i <= 8 ; $i++ ) {
    my $iface = nftest_get_iface("eth$i");
    `${ovs_dir}/utilities/ovs-dpctl del-if dp0 $iface`;
}

`${ovs_dir}/utilities/ovs-dpctl del-dp dp0`;

my $of_kmod_removed = `rmmod openvswitch_mod`;
if ( $of_kmod_removed ne "" ) {
    die "failed to remove kernel module... please fix!\n";
}

$of_kmod_loaded = `lsmod | grep openvswitch_mod`;
if ( $of_kmod_loaded ne "" ) {
    die "failed to remove kernel module... please fix!\n";
}
