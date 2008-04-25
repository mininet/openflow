#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Error qw(:try);
use Data::HexDump;
use Data::Dumper;
use Getopt::Long;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

my $mapFile;
# Process command line options
unless ( GetOptions ("map=s" => \$mapFile,)) { 
	usage(); 
	exit 1;
}

if (defined($mapFile)) {
        nftest_process_iface_map($mapFile);
}

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ("eth1", "eth2", "eth3", "eth4");

my $pkt_args = {
	DA => "00:00:00:00:00:02",
	SA => "00:00:00:00:00:01",
	src_ip => "192.168.0.40",
	dst_ip => "192.168.1.40",
	ttl => 64,
	len => 64
};
my $pkt = new NF2::IP_pkt(%$pkt_args);

my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_PACKET_OUT'},
        length => $ofp->sizeof('ofp_packet_out') + length($pkt->packed), # should generate automatically!
        xid => 0x0000abcd
};
my $packet_out_args = {
        header => $hdr_args,
	buffer_id => -1, # data included in this packet
	in_port => $enums{'OFPP_NONE'},
	out_port => 0 # send out eth1        
};
my $packet_out = $ofp->pack('ofp_packet_out', $packet_out_args);

my $pkt_sent = $packet_out . $pkt->packed;

my $sock = createControllerSocket('localhost');

my $pid;
# Fork off the "controller" server
if ( !( $pid = fork ) ) {

	# Wait for controller to setup socket 
	sleep .1;

	# Spawn secchan process
	exec "secchan", "-v", "nl:0", "tcp:127.0.0.1";
	die "Failed to launch secchan: $!";
}
else {
	# Wait for secchan to connect
	my $new_sock = $sock->accept();

        # launch PCAP listenting interface
        nftest_init(\@ARGV,\@interfaces,);
        nftest_start(\@interfaces,);

        # Send 'packet_out' message
        print $new_sock $pkt_sent;

	nftest_expect(nftest_get_iface('eth5'), $pkt->packed);

	# Wait for test to finish
	sleep(1);
	
	# Kill secchan process
	`killall secchan`;
	
 	my $unmatched = nftest_finish();
	print "Checking pkt errors\n";
	my $total_errors = nftest_print_errors($unmatched);
	
	# Kill secchan process
	close($sock);
        
	my $exitCode;
	if ( $total_errors == 0 ) {
		print "SUCCESS!\n";
		$exitCode = 0;
        }
        else {
		print "FAIL: $total_errors errors\n";
		$exitCode = 1;
        }

        # Exit with the resulting exit code
        exit($exitCode);
}
