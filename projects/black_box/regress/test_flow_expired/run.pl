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

my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_FLOW_MOD'},
        length => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'), # need to replace later
        xid => 0x0000abcd
};

my $match_args = {
        wildcards => 0,
        in_port => 0,
        dl_src => [ 0, 0, 0, 0, 0, 1 ],
        dl_dst => [ 0, 0, 0, 0, 0, 2 ],
        dl_vlan => 0,
        dl_type => 0x800,
        nw_src => 0xc0a80028, #192.168.0.40
        nw_dst => 0xc0a80029, #192.168.0.41
        nw_proto => 17, #tcp
        tp_src => 0x12,
        tp_dst => 0x34
};

my $action_output_args = {
        max_len => 0, # send entire packet
        port => 1
};

my $action_args = {
        type => $enums{'OFPAT_OUTPUT'},
        arg => { output => $action_output_args }
};
my $action = $ofp->pack('ofp_action', $action_args);

my $flow_mod_args = {
        header => $hdr_args,
        match => $match_args,
        command => $enums{'OFPFC_ADD'},
        max_idle => 1,
        buffer_id => -1,
        group_id => 0
};
my $flow_mod = $ofp->pack('ofp_flow_mod', $flow_mod_args);

my $pkt = $flow_mod . $action;

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
	print $new_sock $pkt;

	my $recvd_mesg;
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
