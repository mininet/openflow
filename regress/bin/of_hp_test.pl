#!/usr/bin/perl -w

##############################################################################
#
# Wrapper for running OpenFlow regression tests against ProCurve 3500/5400
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

# For the 5406zl and 3500yl...

# HP switch starts at port 1 == 'A1' or 1 == '1'
# Test need extra delay due to slow controller socket
# Add more idle time due to stat resolution
# byte count is not available - Jean II
push @ARGV, "--root=$ENV{'OFT_ROOT'}", "--common-st-args=hp", "--controller=".$ENV{'OFT_HP_CONTROLLER'}, "--port_base=1", "--send_delay=300000", "--base_idle=2", "--ignore_byte_count";

# Use a single random port instead of all four
push @ARGV, "--less_ports";

# For QinQ, you will need the premium license...
push @ARGV, "--no_vlan";

# The hardware can not support slicing
push @ARGV, "--no_slicing";

# The hardware can not support barrier
push @ARGV, "--no_barrier";

# The hardware can not support emergency flow table
push @ARGV, "--no_emerg";

# Check for listener
if ( defined($ENV{'OFT_HP_LISTENER'}) ) {
    push @ARGV, "--listener=$ENV{OFT_HP_LISTENER}";
}

# Check for specific MAP file...
if ( defined($ENV{'OFT_HP_MAP_ETH'}) ) {
    push @ARGV, "--map=$ENV{OFT_HP_MAP_ETH}";
}

# Other configuration is through Environment Variables, See of_hp_setup.pl
# Jean II

run_regress_test( \&INT_Handler, @ARGV );
