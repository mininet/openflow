#!/usr/bin/perl -w

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;
use Time::HiRes qw(usleep); 

my $mapFile;
my $of_hp_switch_ip;
my $of_hp_vlan;
my $of_hp_controller;
my $of_hp_listener;
my $of_hp_community;

# Process command line options
# Don't fail on unrecognised options, those failures are tricky
# to diagnose. For example projects/controller_disconnect sets --emerg
# Jean II
Getopt::Long::Configure( 'pass_through' );
GetOptions( "map=s" => \$mapFile, );
Getopt::Long::Configure( 'default' );

# If not specified on command line, use environment variable.
# Try specific first, then try generic - Jean II
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_HP_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_HP_MAP_ETH}";
}
if ( (! defined($mapFile) ) && (defined($ENV{'OFT_MAP_ETH'})) ) {
    $mapFile = "$ENV{OFT_MAP_ETH}";
}

if ( defined($mapFile) ) {
	nftest_process_iface_map($mapFile);
}

setup_pcap_interfaces();

# Get HP switch address and configuration - Jean II
if (defined($ENV{'OFT_HP_SWITCH_IP'})) {
    $of_hp_switch_ip = $ENV{'OFT_HP_SWITCH_IP'};
} else {
    $of_hp_switch_ip = "10.10.10.1";
}
if (defined($ENV{'OFT_HP_VLAN'})) {
    $of_hp_vlan = $ENV{'OFT_HP_VLAN'};
} else {
    $of_hp_vlan = 18;
}
if (defined($ENV{'OFT_HP_CONTROLLER'})) {
    $of_hp_controller = $ENV{'OFT_HP_CONTROLLER'};
} else {
    my $of_port = get_of_port();
    $of_hp_controller = "tcp:10.10.10.2:$of_port";
}
if (defined($ENV{'OFT_HP_LISTENER'})) {
    # Transform into a passive string
    ($proto, $host, $port) = split(/:/,$ENV{'OFT_HP_LISTENER'});
    $of_hp_listener = "p$proto:$port";
}
if (defined($ENV{'OFT_HP_COMMUNITY'})) {
    $of_hp_community = $ENV{'OFT_HP_COMMUNITY'};
} else {
    $of_hp_community = 'public';
}


# disable OpenFlow module to make sure it restarts
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.2.${of_hp_vlan} i 2`;

# Make sure the snmp commands don't coalesce
usleep(200000);

# set OpenFlow Controller string
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.3.${of_hp_vlan} s ${of_hp_controller}`;

# set OpenFlow Listener string
if (defined($of_hp_listener)) {
    `snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.4.${of_hp_vlan} s ${of_hp_listener}`;
}

# enable OpenFlow module
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.2.${of_hp_vlan} i 1`;

# Starting OpenFlow takes time, give switch a bit of time...
usleep(900000);
