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
use Getopt::Long;

my $test="Failover test 1 (startup failover)";

my $controllers;

# Remove '--controller' from the option list... - Jean II
Getopt::Long::Configure( 'pass_through' );
GetOptions(
		"controller=s"		=> \$controllers
);
if (!defined($controllers))
{
    # If no controllers specified, use default
    $controllers = nftest_default_controllers();
}
Getopt::Long::Configure( 'default' );

# Get controller
my @controller_array = split(/,/, $controllers);
my $failover_controller = @controller_array[1];

# Push back a controller string
push( @ARGV, "--controller=$failover_controller" );

print "$test: Calling run_black_box_test with @ARGV\n";

sub startup_failover_test {
   print "$test: Failed over successfully\n";
}

run_black_box_test( \&startup_failover_test, \@ARGV );

