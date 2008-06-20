#!/usr/bin/perl -w
# test_receive_bandwidth_fixed

use strict;
use OF::Includes;

use Time::HiRes qw (sleep gettimeofday tv_interval usleep);

my $pkts_total = 10000;
my $pkt_size = 64;
#my $pkt_size = 1512 - $ofp->sizeof( 'ofp_packet_in');

sub verify_packet_in {

	my ( $recvd_mesg, $pkt ) = @_;

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $pkt->packed );
	if ( $msg_size != $expected_size ) { return 1; }

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	# Verify fields
	if (   ( $$msg{'header'}{'version'} != 1 )
		|| ( $$msg{'header'}{'type'} != $enums{'OFPT_PACKET_IN'} )
		|| ( $$msg{'header'}{'length'} != $msg_size )
		|| ( $$msg{'total_len'} != length( $pkt->packed ) )
		|| ( $$msg{'in_port'} != 0 )
		|| ( $$msg{'reason'} != $enums{'OFPR_NO_MATCH'} ) )
	{
		return 1;
	}

	# verify packet was unchanged!
	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
	if ( $recvd_pkt_data ne $pkt->packed ) { return 1; }
}

sub receive_fixed_bandwidth {
	my ( $num_packets, $sock, $pkt, $interface ) = @_;
	my $length      = length( $pkt->packed );
	print "sending $num_packets packets\n";

	my @start_time = gettimeofday();

	my $errors = 0;

	for ( my $count = 0 ; $count < $num_packets ; $count++ ) {

		nftest_send( nftest_get_iface($interface), $pkt->packed );

		my $recvd_mesg;
		sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

		$errors += verify_packet_in( $recvd_mesg, $pkt );
	}

	my $sending_time = tv_interval( \@start_time );
	print "time elapsed: $sending_time\n";
	print "errors: $errors\n";

	my $bps = ($num_packets - $errors) * $length * 8 / $sending_time;
	printf "bandwidth achieved:  %.0f bps \n", $bps;

	return $errors;
}

sub my_test {

	my ($sock) = @_;

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.200.40",
		dst_ip => "192.168.201.40",
		ttl    => 64,
		len    => $pkt_size
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	my $errors = &receive_fixed_bandwidth( $pkts_total, $sock, $pkt, 'eth1' );

	if ($errors > 0) { die "received errors"; }
}

run_black_box_test( \&my_test );

