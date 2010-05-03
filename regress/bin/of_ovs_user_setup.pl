#!/usr/bin/perl -w
# Jean Tourrilhes - HP-Labs

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;

my $mapFile;

# The map file is necessary. It assing the real interface to the
# fictious names used by the test suite.
# eth1->eth4 are capture interfaces used to send/receive probe packets
# eth5->eth8 are configured to run the OpenFlow switch
# Jean II

# Process command line options
# Don't fail on unrecognised options, those failures are tricky
# to diagnose. For example projects/controller_disconnect sets --emerg
# Jean II
Getopt::Long::Configure( 'pass_through' );
GetOptions( "map=s" => \$mapFile, );
Getopt::Long::Configure( 'default' );

# If not specified on command line, use enviroment variable.
# Try specific first, then try generic - Jean II
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_OVS_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_OVS_MAP_ETH}";
}
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_MAP_ETH}";
}

# Set up the mappings
if ( defined($mapFile) ) {
	nftest_process_iface_map($mapFile);
}

# Debug...
#for ( my $i = 1 ; $i <= 8 ; $i++ ) {
#    my $iface = nftest_get_iface("eth$i");
#    print "iface($i) = $iface\n";
#}

# Start capturing on eth1->eth4
setup_pcap_interfaces();

# Get the directly where Open vSwitch resides
my $ovs_dir = $ENV{'OFT_OVS_ROOT'};
my $of_port = get_of_port();

# create command line arguments containing all four ports
my $if_string = '';
for ( my $i = 5 ; $i <= 7 ; $i++ ) {
    $if_string .= nftest_get_iface("eth$i") . ',';
}
$if_string .= nftest_get_iface("eth8");

# create userspace Open vSwitch openflow switch on four ports
system("${ovs_dir}/utilities/ovs-openflowd netdev\@br0 --ports=${if_string} tcp:127.0.0.1:${of_port} --listen=ptcp:6634 --fail=closed --inactivity-probe=999999 &");
