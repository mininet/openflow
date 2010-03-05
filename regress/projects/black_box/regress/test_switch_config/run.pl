#!/usr/bin/perl -w
# test_switch_config

use strict;
use OF::Includes;

sub my_test {

	my ($sock, $options_ref) = @_;

	my $msg = get_config( $ofp, $sock );

	# Verify that the miss_send_len is set to the correct default
	compare( "miss send len", $$msg{'miss_send_len'}, '==', get_of_miss_send_len_default() );

	# As of OF v0.8.1, there was no default for flags - we assume 0
	# (don't send flow expiration messages)
	compare( "flags", $$msg{'flags'}, '==', 0 );
	
	# Now, we change the config and check that it has been committed
	
	# Set flag OFPC_SEND_FLOW_EXP, which has val 1, and should cause flow exps
	my $flags = 1;

	# Change miss_send_len from the default
	my $miss_send_len = 0x100;
	
	set_config($ofp, $sock, $options_ref, $flags, $miss_send_len);
	
	# Give OF switch time to process the set_config
	usleep($$options_ref{'send_delay'});

	$msg = get_config( $ofp, $sock );
	
	compare( "miss send len", $$msg{'miss_send_len'}, '==', $miss_send_len );
	compare( "flags", $$msg{'flags'}, '==', $flags );	
}

run_black_box_test( \&my_test, \@ARGV );

