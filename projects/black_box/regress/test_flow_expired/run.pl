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

my $hdr_args_control = {
        version => 1,
        type => $enums{'OFPT_CONTROL_HELLO'},
        length => 16, # should generate automatically!
        xid => 0x00000000
};
my $control_hello_args = {
        header => $hdr_args_control,
        version => 1, # arbitrary, not sure what this should be
        flags => 1, # ensure flow expiration sent!
        miss_send_len => 0x0080
};
my $control_hello = $ofp->pack('ofp_control_hello', $control_hello_args);

my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'),
        xid => 0x0000000
};

my $match_args = {
        wildcards => 0,
        in_port => 1,
        dl_src => [ 0, 0, 0, 0, 0, 2 ],
        dl_dst => [ 0, 0, 0, 0, 0, 1 ],
        dl_vlan => 0xffff,
        dl_type => 0x800,
        nw_src => 0xc0a80128, #192.168.1.40
        nw_dst => 0xc0a80028, #192.168.0.40
        nw_proto => 0xff, #tcp
        tp_src => 0,
        tp_dst => 0
};

my $action_output_args = {
        max_len => 0, # send entire packet
        port => 0
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
        max_idle => 0x1, 
        buffer_id => 0x0102,
        group_id => 0
};
my $flow_mod = $ofp->pack('ofp_flow_mod', $flow_mod_args);

my $pkt = $flow_mod . $action;
# removed ."\0\0\0\0";

print HexDump($pkt);

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

        # Send 'control_hello' message
        print $new_sock $control_hello;

        my $recvd_mesg;
        sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	print "received message after control hello\n";
	
	# Send 'flow_mod' message
	print $new_sock $pkt;

	print "sent second message\n";

	#my $recvd_mesg;
	sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	
	# Kill secchan process
	`killall secchan`;

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_expired');
	compare ("msg size", length($recvd_mesg), '==', $expected_size);

	my $msg = $ofp->unpack('ofp_flow_expired', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	print Dumper($msg);

	# Verify fields
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_FLOW_EXPIRED'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);

	# compare all fields of match

	# compare other fields	

	close($sock);

	print "SUCCESS!\n";
	exit 0;
}
