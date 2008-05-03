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

my @tcp_payload = (      # 30 bytes
    0x00,0x46,0x00,0x50, #SrcPort=70, DstPort=80,
    0x01,0x23,0x45,0x67, #Seq
    0x01,0x23,0x45,0x00, #Ack
    0x18,0x23,0x00,0x11, #Offset, Flag, Win
    0xaa,0xbb,0x00,0x00, #Chksum, Urgent
    0x03,0x03,0x02,0x00,  #TCP Option
    0xaa,0xbb,0xcc,0xdd,  #TCP Content
    0xee,0xff  #TCP Content
);

my $tcp_op_pkt_args = {
    DA => "02:02:02:02:02:02",
    SA => "01:01:01:01:01:01",
    ip_hdr_len => 5, 
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 64,
    len => 64, # len = 14+20+30=64 (IPlen=50)
    proto => 6
};

my $test_tcp_op_pkt = new NF2::IP_pkt(%$tcp_op_pkt_args);
my $payload=$test_tcp_op_pkt->{'payload'};
$$payload->set_bytes(@tcp_payload);

print "print pkt\n";
print HexDump($test_tcp_op_pkt->packed);
print "--------------------------\n";

my $ip_protocol= 6;
my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action') + 4, # need to replace later
        xid => 0x0000000
};

my $match_args = {
        wildcards => 0,
        in_port => 2, # '2' means 'eth3'
        dl_src => [ 1, 1, 1, 1, 1, 1 ],
        dl_dst => [ 2, 2, 2, 2, 2, 2 ],
        dl_vlan => 0xffff, # not used unless dl_type is 0x8100.
        dl_type => 0x800,
        nw_src => 0xc0a80128, #192.168.1.40
        nw_dst => 0xc0a80028, #192.168.0.40
        nw_proto => $ip_protocol,
        tp_src => 70, # should not used for matching unless nw_proto is TCP or UDP.
        tp_dst => 80  # should not used for matching unless nw_proto is TCP or UDP.
};

my $action_output_args = {
        max_len => 0xffff, # send entire packet
        port => 3  #'3' means eth4 
};

my $action_args = {
        type => $enums{'OFPAT_OUTPUT'},
        arg => { output => $action_output_args }
};
my $action = $ofp->pack('ofp_action', $action_args);

# not sure why either two actions are being sent or structure packing is off.
my $flow_mod_args = {
        header => $hdr_args,
        match => $match_args,
        command => $enums{'OFPFC_ADD'},
        max_idle => 0x0,
        buffer_id => 0x0102,
        group_id => 0
#        priority => 0x1111
};
my $flow_mod = $ofp->pack('ofp_flow_mod', $flow_mod_args);
my $pkt = $flow_mod . $action . "\0\0\0\0";
print HexDump($pkt);

my $pkt_args = {
    DA => "02:02:02:02:02:02",
    SA => "01:01:01:01:01:01",
#    ip_hdr_len => 5 + ($#ipopt + 1)/4,
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 64,
    len => 148,
    src_port => 70,
    dst_port => 80,
};
my $test_pkt = new NF2::UDP_pkt(%$pkt_args);
my $iphdr=$test_pkt->{'IP_hdr'};
$$iphdr->proto($ip_protocol); #set protocol

print "print tcp pkt\n";
print HexDump($test_pkt->packed);
print "--------------------------\n";

my $hdr_args_control = {
        version => 1,
        type => $enums{'OFPT_CONTROL_HELLO'},
        length => 16, # should generate automatically!
        xid => 0
};

my $control_hello_args = {
        header => $hdr_args_control,
        version => 1, # arbitrary, not sure what this should be
        flags => 1, # ensure flow expiration sent!
        miss_send_len => 0x0080
};
my $control_hello = $ofp->pack('ofp_control_hello', $control_hello_args);


###############
my $sock = createControllerSocket('localhost');
my $pid;
# Fork off the "controller" server
if ( !( $pid = fork ) ) {

	# Wait for controller to setup socket 
	sleep .1;

	# Spawn secchan process
	print "spawn sechan\n";
	exec "secchan", "nl:0", "tcp:127.0.0.1";
	die "Failed to launch secchan: $!";
}
else {
	
	# Wait for secchan to connect
	my $new_sock = $sock->accept();

        # Send 'control_hello' message
	print "Send control_hello\n";
        print $new_sock $control_hello;

        my $recvd_mesg;
        sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	print "received message after control hello\n";
	my $hello_res=$ofp->unpack('ofp_packet_in',$recvd_mesg);
	compare("header version", $$hello_res{'header'}{'version'}, '==', 1);
	compare("header type", $$hello_res{'header'}{'type'}, '==', $enums{'OFPT_DATA_HELLO'});
	print HexDump ($recvd_mesg);
	print Dumper($hello_res);

	# Send 'flow_mod' message (install fwd table)
	print $new_sock $pkt;
	print "sent second message\n";
	sleep(1);
	
	# sending/receiving interfaces - NOT OpenFlow ones
	my @interfaces = ("eth1", "eth2", "eth3", "eth4");
	nftest_init(\@ARGV,\@interfaces,);
	nftest_start(\@interfaces,);


#	nftest_expect('eth4', $test_pkt->packed);
#	nftest_send('eth3', $test_pkt->packed);

	nftest_expect('eth4', $test_tcp_op_pkt->packed);
	nftest_send('eth3', $test_tcp_op_pkt->packed);

	sleep(3);

	my $total_errors = 0;

	### Check CTRL Channel
        print $new_sock $control_hello;
	sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	# Kill secchan process
	`killall secchan`;
	# Inspect  message
	# Verify fields
	my $hello_res2 = $ofp->unpack('ofp_packet_in', $recvd_mesg);
	compare("header version", $$hello_res2{'header'}{'version'}, '==', 1);
	if ( $$hello_res2{'header'}{'type'} == $enums{'OFPT_PACKET_IN'} ){
		print "Short packet is forwarded to secchan as OFPT_PACKET_IN".$$hello_res2{'header'}{'type'}."\n";
	        $total_errors ++;	
	}
	print "received message after 2nd control hello\n";
	print HexDump ($recvd_mesg);
	print Dumper($hello_res2);

	`killall secchan`;

        ### Check ethernet ports
 	my $unmatched = nftest_finish();
	print "Checking pkt errors\n";

	$total_errors += nftest_print_errors($unmatched);
	
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
