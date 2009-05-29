#!/usr/bin/perl

# Simple two-controller failover test
#
# For this test to work, the switch must be set up to use our
# two "controllers", e.g.
#
# ofprotocol --controller=tcp:127.0.0.1:6633,tcp:127.0.0.1:6634
#
# If you use different ports than the defaults, then you must
# pass the --controller option into this script as well.
#
# Failover Test 1: Startup Failover
#
# For this test, we listen on the second controller port rather
# than the first.
#

use strict;
use OF::Includes;

my $test="Failover test 1 (startup failover)";

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

print "$test: Calling run_black_box_test with @ARGV\n";

sub startup_failover_test {
   print "$test: Failed over successfully\n";
}

run_black_box_test( \&startup_failover_test, \@ARGV );

