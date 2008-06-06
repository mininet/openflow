#!/usr/bin/perl -w

##############################################################################
#
# Wrapper for OpenFlow regression tests
# $Id$
#
##############################################################################

use OF::Base;
use Test::RegressTest;
use strict;

# check vars are set.
check_OF_vars_set();

sub INT_Handler {
	my $signame = shift;
	print "\nNo interrupt handler implemented yet...\n";
	print "\nExited with SIG$signame\n";
	exit(1);
}

push @ARGV, "--root=$ENV{'OFT_ROOT'}";

run_regress_test( \&INT_Handler, @ARGV );
