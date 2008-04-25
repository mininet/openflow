#!/usr/bin/perl -w

##############################################################################
#
# Wrapper for OpenFlow regression tests
# $Id$
#
##############################################################################

use OF::Base;
use strict;

# check vars are set.
check_OF_vars_set();

my $_NF2_ROOT       = $ENV{'NF2_ROOT'};
my $_OFT_ROOT       = $ENV{'OFT_ROOT'};

my @args = ("${_NF2_ROOT}/bin/nf21_regress_test.pl", "--root=${_OFT_ROOT}", 
	"--netfpga=false", @ARGV);
system(@args) == 0
	or die "Failure running OpenFlow tests: $?"