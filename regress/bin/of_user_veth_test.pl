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

push( @ARGV, "--map=$ENV{'OFT_ROOT'}/bin/veth.map", "--root=$ENV{'OFT_ROOT'}", "--port_base=1", "--common-st-args=user_veth");

run_regress_test( \&INT_Handler, @ARGV );
