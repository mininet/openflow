#!/usr/bin/perl -w
# test_hello

use strict;
require OF::Includes;

sub my_test {

	my ($sock, $options_ref) = @_;
	


	# hello sequence automatically done by test harness!
}
	
run_black_box_test( \&my_test, \@ARGV );
