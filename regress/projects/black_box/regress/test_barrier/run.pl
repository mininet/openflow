#!/usr/bin/perl -w
# test_barrier

use strict;
use OF::Includes;

sub my_test {
    my ($sock, $options_ref) = @_;

    if ( not defined( $$options_ref{'no_barrier'} ) ) {
	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;

	# RUOK?
	send_get_config_request($ofp, $sock, 0xdeadbeef);
	wait_for_get_config_reply($ofp, $sock, 0xdeadbeef);

	my $base_packet = get_default_black_box_pkt($in_port, $out_port);

	my $wildcards = 0x0000;
	my $flags = $enums{'OFPFF_CHECK_OVERLAP'};
	my $max_idle = 0x0;
	my $packet = create_flow_mod_from_udp($ofp, $base_packet, $in_port, $out_port, $max_idle, $flags, $wildcards);

	# FOO
	print $sock $packet;

	my $wildcards = 0x03fe;
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};
	my $packet = create_flow_mod_from_udp($ofp, $base_packet, $in_port, $out_port, $max_idle, $flags, $wildcards);

	# BAR
	print $sock $packet;

	my $wildcards = 0x03fd;
	my $flags = 0x0000;
	my $packet = create_flow_mod_from_udp($ofp, $base_packet, $in_port, $out_port, $max_idle, $flags, $wildcards);

	# BAZ
	print $sock $packet;

	# SYNC
	enter_barrier($ofp, $sock, 0x12345678);
	wait_for_barrier_exit($ofp, $sock, 0x12345678);

	# RUOK?
	send_get_config_request($ofp, $sock, 0xcafe2009);
	wait_for_get_config_reply($ofp, $sock, 0xcafe2009);
    }
}

run_black_box_test(\&my_test, \@ARGV);
