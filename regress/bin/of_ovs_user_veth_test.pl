#!/usr/bin/perl -w

##############################################################################
#
# Wrapper for running OpenFlow regression tests against Open vSwitch
# using veth
# Jean Tourrilhes - HP-Labs - copyright 2009-2010
# $Id: of_regress_test.pl 105 2008-06-06 04:07:05Z brandonh $
#
##############################################################################

use OF::Base;
use Test::RegressTest;
use strict;
use OF::OFUtil;

# check vars are set.
check_OF_vars_set();

sub INT_Handler {
	my $signame = shift;
	print "\nNo interrupt handler implemented yet...\n";
	print "\nExited with SIG$signame\n";
	exit(1);
}

# For Open vSwitch

# Open vSwitch starts at port 1
# Get a bit of speedup by tweaking send_delay and base_idle
# Jean II
my $of_port = get_of_port();
push @ARGV, "--root=$ENV{'OFT_ROOT'}", "--common-st-args=ovs_user", "--controller=tcp:localhost:$of_port,tcp:localhost:$of_port", "--listener=tcp:127.0.0.1:6634", "--port_base=1", "--send_delay=2000", "--base_idle=2", "--map=$ENV{'OFT_ROOT'}/bin/veth.map";

# Use a single random port instead of all four
push @ARGV, "--less_ports";

# Don't bother with QoS currently, it's broken...
push @ARGV, "--no_slicing";

# The bother with emergency flow table tests, it's not supported...
push @ARGV, "--no_emerg";

# Don't forget to configure the OVS_ROOT environment variable
# Jean II

run_regress_test( \&INT_Handler, @ARGV );
