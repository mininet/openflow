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


#00000000  02 02 02 02 02 02 01 01 - 01 01 01 01 08 00 45 00  ..............E.
#00000010  00 2E 00 00 40 00 40 11 - B8 1E C0 A8 01 28 C0 A8  ....@.@......(..
#00000020  00 28 00 46 00 50 00 1A - 02 01 9B 5E EF 7F 53 F6  .(.F.P.....^..S.
#00000030  9D 6C 8C 35 C5 88 63 A7 - B3 E9 94 F1              .l.5..c.....

my $test_pkt_llc_ip = new NF2::PDU(68);
@{$test_pkt_llc_ip->{'bytes'}}[0..67] = (
              0x02,0x02,0x02,0x02,0x02,0x02, # 6byte
	      0x04,0x04,0x04,0x04,0x04,0x04, # 6byte
              0x00,0x36,                     # 2byte (Length=56byte=0x0036)
	      0xAA,0xAA,0x03, #LLC           # 3byte
	      0x00,0x00,0x00, #SNAP(OUI)    # 3byte
	      0x08,0x00, #SNAP(PID)         # 2byte (0x0800 = IP)
	      0x45,0x00,0x00,0x2E,           # 46 byte
	      0x00,0x00,0x40,0x00,
	      0x40,0x11,0xB8,0x1E,
	      0xC0,0xA8,0x01,0x28,
	      0xC0,0xA8,0x00,0x28,
	      0x00,0x46,0x00,0x50,
	      0x00,0x1A,0xCD,0x3F,
	      0xAE,0xA5,0x7F,0x87,
	      0xEE,0x67,0x72,0xA7,
	      0x17,0x91,0xFE,0x10,
	      0xBD,0xFA,0xC0,0xC2,
	      0x8B,0xA7);
print "print llc pkt\n";
print HexDump($test_pkt_llc_ip->packed);
print "--------------------------\n";

my $test_pkt_raw_ip = new NF2::PDU(60);
@{$test_pkt_raw_ip->{'bytes'}}[0..59] = (
              0x02,0x02,0x02,0x02,0x02,0x02, # 6byte
	      0x04,0x04,0x04,0x04,0x04,0x04, # 6byte
              0x08,0x00,                     # 2byte (Type=IP)
	      0x45,0x00,0x00,0x2E,           # 46 byte
	      0x00,0x00,0x40,0x00,
	      0x40,0x11,0xB8,0x1E,
	      0xC0,0xA8,0x01,0x28,
	      0xC0,0xA8,0x00,0x28,
	      0x00,0x46,0x00,0x50,
	      0x00,0x1A,0x02,0x01,
	      0x9B,0x5E,0xEF,0x7F,
	      0x53,0xF6,0x9D,0x6C,
	      0x8C,0x35,0xC5,0x88,
	      0x63,0xA7,0xB3,0xE9,
	      0x94,0xF1);
print "print ip raw pkt\n";
print HexDump($test_pkt_raw_ip->packed);
print "--------------------------\n";

my $ip_protocol=0x11;
my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action') + 4, # need to replace later
        xid => 0x0000000
};
my $match_args = {
        wildcards => 0,
        in_port => 2, # '2' means 'eth3'
        dl_src => [ 4, 4, 4, 4, 4, 4 ],
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
#        port => $enums{'OFPP_LOCAL'} 
#        port => $enums{'OFPP_NONE'} 
#        port => $enums{'OFPP_CONTROLLER'} 
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

#my @ipopt=(0x44,0x08,0x08,0x00,0x11,0x22,0x33,0x44); #IP timestamp option
my $pkt_args = {
    DA => "02:02:02:02:02:02",
    SA => "04:04:04:04:04:04",
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 0xff,
    len => 60,
    src_port => 70,
    dst_port => 80,
#    ip_options => \@ipopt 
};
my $test_pkt = new NF2::UDP_pkt(%$pkt_args);
my $iphdr=$test_pkt->{'IP_hdr'};
#$$iphdr->ip_hdr_len(5+($#ipopt+1)/4); #set ip_hdr_len correctly
$$iphdr->proto($ip_protocol); #set protocol

print "print pkt\n";
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

#	nftest_expect(nftest_get_iface('eth4'), $test_pkt->packed);
#	nftest_send(nftest_get_iface('eth3'), $test_pkt->packed);

	nftest_expect(nftest_get_iface('eth4'), $test_pkt_llc_ip->packed);
	nftest_send(nftest_get_iface('eth3'), $test_pkt_llc_ip->packed);

#	nftest_expect(nftest_get_iface('eth4'), $test_pkt_raw_ip->packed);
#	nftest_send(nftest_get_iface('eth3'), $test_pkt_raw_ip->packed);

	sleep(1);

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
