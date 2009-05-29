#!/usr/bin/perl

# Simple two-controller failover test
#
# Failover Test #1: Startup Failover
#
# For this test to work, the switch must be set up to use our
# two "controllers", e.g.
#
# ofprotocol --controller=tcp:127.0.0.1:6633,tcp:127.0.0.1:6634
#
# If you use different ports than the defaults, then you must
# pass the --controller option into this script as well
#

use strict;
use OF::Includes;

# If no controllers specified, use default
if  (not @ARGV =~ "--controller") {
   push( @ARGV, "--controller=" . nftest_default_controllers() );
}

# Replace --controller=foo,bar with --controller=bar so that
# run_black_box_test() will use bar's port rather than foo's
for (my $i = 0; $i < @ARGV; $i++) {
   if ($ARGV[$i] =~ /controller=[^,]*,([^\s]+)/ ) {
      print "failover_startup: got controller $1\n";
      $ARGV[$i] = "--controller=$1";
   }
}

"Startup Failover Test: calling run_black_box_test with @ARGV\n";

sub startup_failover_test {
   print "Startup Failover Test: failed over successfully\n";
}

run_black_box_test( \&startup_failover_test, \@ARGV );

