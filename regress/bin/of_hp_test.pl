#!/usr/bin/perl -w

##############################################################################
#
# Wrapper for OpenFlow regression tests
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

# HP switch starts at port 1 == A1
# Test need extra delay due to slow controller socket (local buffers ?)
# Add more idle time due to stat resolution
# byte count is not available - Jean II
push @ARGV, "--root=$ENV{'OFT_ROOT'}", "--common-st-args=hp", "--controller=".$ENV{'OFT_HP_CONTROLLER'}, "--port_base=1", "--send_delay=500000", "--base_idle=3", "--ignore_byte_count", "--less_ports";

# Other configuration is through Environment Variables, See of_hp_setup.pl
# Jean II

run_regress_test( \&INT_Handler, @ARGV );
