#!/usr/bin/perl -w
# test_packet_in

use strict;
use OF::Includes;

sub my_test {
	
	my ($sock) = @_;
	
	my $pkt_args = {
		DA => "00:00:00:00:00:02",
		SA => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl => 64,
		len => 256
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	nftest_send(nftest_get_iface('eth1'), $pkt->packed);

	my $recvd_mesg;
	sysread($sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof('ofp_packet_in', 'data') + get_of_miss_send_len_default();
	compare ("msg size", $msg_size, '==', $expected_size);

	my $msg = $ofp->unpack('ofp_packet_in', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header($msg, 'OFPT_PACKET_IN', $msg_size);

	# total len should be full length of original sent frame
	compare("total len", $$msg{'total_len'}, '==', length($pkt->packed));
	compare("in_port", $$msg{'in_port'}, '==', 0);
	compare("reason", $$msg{'reason'}, '==', $enums{'OFPR_NO_MATCH'});

	# verify packet was unchanged!
	my $recvd_pkt_data = substr ($recvd_mesg, $ofp->offsetof('ofp_packet_in', 'data'));
	# trim to MISS_SEND_LEN
	my $pkt_trimmed = substr ($pkt->packed, 0, get_of_miss_send_len_default());
	if ($recvd_pkt_data ne $pkt_trimmed) {
		die "ERROR: received packet data didn't match packet sent\n";
	}
}

# Send a packet of size 256B, and ensure that it gets reduced to 128B
run_black_box_test(\&my_test);