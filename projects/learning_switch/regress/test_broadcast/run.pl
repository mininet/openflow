#!/usr/bin/perl -w
# test_broadcast

use strict;
use OF::Includes;

sub gen_broadcast_pkt {
	my ($portNum) = shift;

	my $pkt_args = {
		DA     => "FF:FF:FF:FF:FF:FF",
		SA     => "00:00:00:00:00:0" . $portNum,
		src_ip => "192.168." . $portNum . ".40",
		dst_ip => "255.255.255.255",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);
	return $pkt;
}

sub send_expect_broadcast {
	my ( $portNum, $pkt, $delta_ref ) = @_;

	send_and_count( 'eth' . $portNum, $pkt->packed, $delta_ref );
	for ( my $i = 1 ; $i <= 4 ; $i++ ) {
		if ( $i != $portNum ) {
			expect_and_count( 'eth' . $i, $pkt->packed, $delta_ref );
		}
	}
}

sub my_test {

	my %delta;

	for ( my $i = 1 ; $i < 4 ; $i++ ) {
		my $pkt = gen_broadcast_pkt($i);

		# send one broadcast packet, then do it again on the same port
		send_expect_broadcast( $i, $pkt, \%delta );
		sleep 0.1;
		send_expect_broadcast( $i, $pkt, \%delta );
		sleep 0.1;
	}

	return %delta;
}

run_learning_switch_test( \&my_test, \@ARGV );
