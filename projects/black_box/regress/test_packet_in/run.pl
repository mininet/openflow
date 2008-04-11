#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Error qw(:try);
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ("eth5", "eth6", "eth7", "eth8");

my $sock = createControllerSocket('localhost');

my $pid;
# Fork off the "controller" server
if ( !( $pid = fork ) ) {

	# Wait for controller to setup socket 
	sleep .1;

	# Spawn secchan process
	exec "secchan", "nl:0", "tcp:127.0.0.1";
	die "Failed to launch secchan: $!";
}
else {
	# Wait for secchan to connect
	my $new_sock = $sock->accept();

        # launch PCAP listenting interface
        nftest_init(\@ARGV,\@interfaces,);
        nftest_start(\@interfaces,);
	
	my $pkt_args = {
		DA => "00:00:00:00:00:02",
		SA => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl => 64,
		len => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	nftest_send('eth5', $pkt->packed);

	my $recvd_mesg;
	sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	
	# Kill secchan process
	`killall secchan`;

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	
	print "sizeof ofp packet in: " . $ofp->sizeof('ofp_packet_in') . "\n";
	my $expected_size = $ofp->sizeof('ofp_packet_in') + length($pkt->packed);
	compare ("msg size", $msg_size, '==', $expected_size);

	my $msg = $ofp->unpack('ofp_packet_in', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	print Dumper($msg);

	# Verify fields
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_PACKET_IN'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);

	compare("total len", $$msg{'total_len'}, '==', length($pkt->packed));
	compare("in_port", $$msg{'in_port'}, '==', 0);
	compare("reason", $$msg{'reason'}, '==', $enums{'OFPR_NO_MATCH'});

	# verify packet was unchanged!
	my $recvd_pkt_data = substr ($recvd_mesg, $ofp->sizeof('ofp_packet_in'));
	if ($recvd_pkt_data ne $pkt->packed) {
		die "ERROR: received packet data didn't match packet sent\n";
	}
		
 	my $unmatched = nftest_finish();

	close($sock);

	print "SUCCESS!\n";
	exit 0;
}
