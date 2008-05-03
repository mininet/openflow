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

my $ip_protocol=0x11;

## Wildcard entry  (don't care udp ports)
my $hdr_args1 = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action') + 4, # need to replace later
        xid => 0x0000000
};
my $match_args1 = {
        wildcards => 0x300,
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
my $action_output_args1 = {
        max_len => 0xffff, # send entire packet
        port => 3  #'3' means eth4 
};
my $action_args1 = {
        type => $enums{'OFPAT_OUTPUT'},
        arg => { output => $action_output_args1 }
};
my $action1 = $ofp->pack('ofp_action', $action_args1);

# not sure why either two actions are being sent or structure packing is off.
my $flow_mod_args1 = {
        header => $hdr_args1,
        match => $match_args1,
        command => $enums{'OFPFC_ADD'},
        max_idle => 0x0,
        buffer_id => 0x0102,
        group_id => 0,
        priority => 0x2
};
my $flow_mod1 = $ofp->pack('ofp_flow_mod', $flow_mod_args1);
my $flow_mod_pkt1 = $flow_mod1 . $action1 . "\0\0\0\0";
print HexDump($flow_mod_pkt1);

my $flow_mod_args1_delete = {
        header => $hdr_args1,
        match => $match_args1,
        command => $enums{'OFPFC_DELETE'},
#        command => $enums{'OFPFC_DELETE_STRICT'},
        max_idle => 0x0,
        buffer_id => 0x0102,
        group_id => 0,
};
my $flow_mod_delete1 = $ofp->pack('ofp_flow_mod', $flow_mod_args1_delete);
my $flow_mod_delete_pkt1 = $flow_mod_delete1 . $action1 . "\0\0\0\0";


#　WExact Match entry
my $hdr_args2 = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action') + 4, # need to replace later
        xid => 0x0000000
};
my $match_args2 = {
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
my $action_output_args2 = {
        max_len => 0xffff, # send entire packet
        port => 1  #'1' means eth2
};
my $action_args2 = {
        type => $enums{'OFPAT_OUTPUT'},
        arg => { output => $action_output_args2 }
};
my $action2 = $ofp->pack('ofp_action', $action_args2);

# not sure why either two actions are being sent or structure packing is off.
my $flow_mod_args2 = {
        header => $hdr_args2,
        match => $match_args2,
        command => $enums{'OFPFC_ADD'},
        max_idle => 0x0,
        buffer_id => 0x0102,
        group_id => 0,
};
my $flow_mod2 = $ofp->pack('ofp_flow_mod', $flow_mod_args2);
my $flow_mod_pkt2 = $flow_mod2 . $action2 . "\0\0\0\0";
print HexDump($flow_mod_pkt2);

# Wildcard entry (only care input physical port #) -- not used for now (May 2)
my $hdr_args3 = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action') + 4, # need to replace later
        xid => 0x0000000
};
my $match_args3 = {
        wildcards => 0x3F0,
        in_port => 2, # '2' means 'eth3'
        dl_src => [ 3, 3, 3, 3, 3, 3 ],
        dl_dst => [ 2, 2, 2, 2, 2, 2 ],
        dl_vlan => 0xffff, # not used unless dl_type is 0x8100.
        dl_type => 0x800,
#        nw_src => 0xc0a80128, #192.168.1.40
#        nw_dst => 0xc0a80028, #192.168.0.40
#	nw_proto => $ip_protocol,
#        tp_src => 70, # should not used for matching unless nw_proto is TCP or UDP.
#        tp_dst => 80  # should not used for matching unless nw_proto is TCP or UDP.
};
my $action_output_args3 = {
        max_len => 0xffff, # send entire packet
        port => 0  #'1' means eth1
};
my $action_args3 = {
        type => $enums{'OFPAT_OUTPUT'},
        arg => { output => $action_output_args3 }
};
my $action3 = $ofp->pack('ofp_action', $action_args3);

# not sure why either two actions are being sent or structure packing is off.
my $flow_mod_args3 = {
        header => $hdr_args3,
        match => $match_args3,
        command => $enums{'OFPFC_ADD'},
        max_idle => 0x0,
        buffer_id => 0x0102,
        group_id => 0,
        priority => 0x0
};
my $flow_mod3 = $ofp->pack('ofp_flow_mod', $flow_mod_args3);
my $flow_mod_pkt3 = $flow_mod3 . $action3 . "\0\0\0\0";
print HexDump($flow_mod_pkt3);



#my @ipopt=(0x44,0x08,0x08,0x00,0x11,0x22,0x33,0x44); #IP timestamp option
my $pkt_len = 148;
my $pkt_args = {
    DA => "02:02:02:02:02:02",
    SA => "01:01:01:01:01:01",
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 0xff,
    len => $pkt_len,
    src_port => 70,
    dst_port => 80,
#    ip_options => \@ipopt 
};
my $test_pkt = new NF2::UDP_pkt(%$pkt_args);
my $iphdr=$test_pkt->{'IP_hdr'};
#$$iphdr->ip_hdr_len(5+($#ipopt+1)/4); #set ip_hdr_len correctly
$$iphdr->proto($ip_protocol); #set protocol

my $pkt_args2 = {
    DA => "02:02:02:02:02:02",
    SA => "01:01:01:01:01:01",
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 0xff,
    len => 148,
    src_port => 71,
    dst_port => 81,
#    ip_options => \@ipopt 
};
my $test_pkt2 = new NF2::UDP_pkt(%$pkt_args2);
my $iphdr2=$test_pkt2->{'IP_hdr'};
$$iphdr2->proto($ip_protocol); #set protocol

# pkt3( not used for now, May 2)
my $pkt_args3 = {
    DA => "02:02:02:02:02:02",
    SA => "01:01:01:01:01:01",
    src_ip => "192.168.1.40",
    dst_ip => "192.168.0.40",
    ttl => 0xff,
    len => 148,
    src_port => 0,
    dst_port => 0,
    proto => 0x1
};
my $test_pkt3 = new NF2::IP_pkt(%$pkt_args3);



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
	print $new_sock $flow_mod_pkt1;

	print "Add 1st flow entry(Wildcard A: don't care udp ports)\n";
	sleep(1);
	print $new_sock $flow_mod_pkt2;
	print "Add 2nd flow entry(Exact match)\n";
	sleep(1);

#	print "Add 3nd flow entry(wildcard B: don't cover Widcard A and exact match)\n";	
#	sleep(1);
#	print $new_sock $flow_mod_pkt3;


	# sending/receiving interfaces - NOT OpenFlow ones
	my @interfaces = ("eth1", "eth2", "eth3", "eth4");
	nftest_init(\@ARGV,\@interfaces,);
	nftest_start(\@interfaces,);

	# Pkt matches exact, Wildcard A
	nftest_expect(nftest_get_iface('eth2'), $test_pkt->packed);
	nftest_send(nftest_get_iface('eth3'), $test_pkt->packed);

	# Pkt matches Wildcard A
	nftest_expect(nftest_get_iface('eth4'), $test_pkt2->packed);
	nftest_send(nftest_get_iface('eth3'), $test_pkt2->packed);

	# Pkt only matches wildcard B
#	nftest_expect(nftest_get_iface('eth2'), $test_pkt3->packed);
#	nftest_send(nftest_get_iface('eth1'), $test_pkt3->packed);

	sleep(1);

	# Send 'flow_mod' message (delete wildcard entry with 'DELETE' (not strict));
	print $new_sock $flow_mod_delete_pkt1;
	print "sent delete message (delete wildcard entry with DELETE (not strict))\n";

	sleep(1);

	print "sent pkt matching to the exact match\n";
	nftest_send(nftest_get_iface('eth3'), $test_pkt->packed);

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
	if ( $$hello_res2{'header'}{'type'} != $enums{'OFPT_PACKET_IN'} ){
		print "packet is NOT forwarded to secchan as OFPT_PACKET_IN".$$hello_res2{'header'}{'type'}."\n";
	        $total_errors ++;	
	}else{
	    if ( $$hello_res2{'total_len'} != $pkt_len ){
		print "packet is forwarded to secchan but length is not correct" . "\n";
	        $total_errors ++;	
	    }
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
