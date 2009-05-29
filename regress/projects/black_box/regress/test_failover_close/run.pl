#!/usr/bin/perl -w

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
# Failover test 2: Controller is fine, but closes connection
#
# For this test, we accept the Hello sequence and then close
# the socket. Then we listen for a failover connection on the
# second socket.
#

use strict;
use OF::Includes;

# Save ARGV for future reference
my @ARGS = @ARGV;

my $test = "Failover test 2 (connection closed)";

print "$test phase 1: calling run_black_box_test with @ARGV\n";

# Start up, say Hello, and close connection
sub close_failover_test_phase_1 {
   my ($sock) = @_;
   print "$test: Got socket $sock\n";
   print "$test: Finished Hello sequence on first controller\n";
   print "$test: Closing socket\n";
   $sock->close();
}

run_black_box_test( \&close_failover_test_phase_1, \@ARGV, 1); # 1 -> don't exit

# Now, attempt to open up the second controller connection, and
# hope that we fail over

# Restore ARGV
@ARGV = @ARGS;

# If no controllers specified, use default
if  (not "@ARGV" =~ "--controller") {
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


sub close_failover_test_phase_2 {
   print "$test: Failover to second controller succeeded\n";
}

print "$test: Calling run_black_box_test with @ARGV\n";
run_black_box_test( \&close_failover_test_phase_2, \@ARGV ); # do exit this time

