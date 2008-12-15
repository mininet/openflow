#!/usr/bin/perl -w

use Getopt::Long;

use OF::OFUtil;
use Test::TestLib;
use Time::HiRes qw(usleep); 

my $mapFile;
my $of_hp_switch_ip;
my $of_hp_vlan;
my $of_hp_controller;
my $of_hp_community;

# Process command line options
unless ( GetOptions( "map=s" => \$mapFile, ) ) {
	print "unrecognized option\n";
	exit 1;
}

# If not specified on command line, use enviroment variable - Jean II
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
if (defined($ENV{'OFT_HP_COMMUNITY'})) {
    $of_hp_community = $ENV{'OFT_HP_COMMUNITY'};
} else {
    $of_hp_community = 'public';
}

# disable OpenFlow module to make sure it restarts
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.2.${of_hp_vlan} i 2`;

# Make sure the snmp commands don't coalesce
usleep(300000);

# set OpenFlow Controller string
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.3.${of_hp_vlan} s ${of_hp_controller}`;

# enable OpenFlow module
`snmpset -v2c -c ${of_hp_community} ${of_hp_switch_ip} iso.org.dod.internet.private.enterprises.11.2.14.11.5.1.7.1.35.1.1.2.${of_hp_vlan} i 1`;
