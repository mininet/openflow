#############################################################
# $Id: OFUtil.pm 3161 2007-12-13 21:08:05Z bdh $
#
# Module provides basic functions for use by OF Perl scripts.
#
# Revisions:
#
##############################################################
 
package OF::OFUtil; 

use Getopt::Long;
use Test::TestLib;
use Error qw(:try);
use OF::OFPacketLib;
use Test::PacketLib;
use Exporter;
use Data::Dumper;
use IO::Socket;
use Data::HexDump;

@ISA = ('Exporter');
@EXPORT = qw( 
	&trim 
	&send_and_count 
	&expect_and_count 
	&save_counters 
	&verify_counters 
	&setup_kmod 
	&teardown_kmod
	&compare
	&createControllerSocket
	&run_learning_switch_test
	&do_hello_sequence
	&run_black_box_test 
	&create_flow_mod_from_udp
	&create_flow_mod_from_udp_action
	&wait_for_flow_expired
	&wait_for_flow_expired_one
	&wait_for_flow_expired_size
	&wait_for_flow_expired_total_bytes
	&wait_for_one_packet_in
);

my $nf2_kernel_module_path = 'datapath_nf2/linux-2.6'; 
my $nf2_kernel_module_name = 'openflow_hw_nf2.ko';

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ( "eth1", "eth2", "eth3", "eth4" );

# data length forwarded to the controller if miss (used in do_hello_sequence)
#$OF::OFUtil::miss_send_len = 0x0080; # 128 bytes
my $miss_send_len = 0x0080; # 128 bytes

##############################################################
#
# Check that the user has set up their environment correctly.
#
##############################################################

sub trim($) {
        my $string = shift;
        $string =~ s/^\s+//;
        $string =~ s/\s+$//;
        return $string;
}

sub get_if_rx {
        my $interface = shift;
        return `/sbin/ifconfig $interface | grep \'RX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;
}

sub get_if_tx {
        my $interface = shift;
        return `/sbin/ifconfig $interface | grep \'TX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;
}

sub send_and_count {
	my($interface, $pkt, $counters) = @_;
        nftest_send($interface, $pkt);
        $$counters{$interface}{tx_pkts}++;
}

sub expect_and_count {
        my($interface, $pkt, $counters) = @_;
        nftest_expect($interface, $pkt);
        $$counters{$interface}{rx_pkts}++;
}

sub save_counters {
        my $counters = @_;
	foreach my $i (keys %counters) {
                $$counters{$i}{rx_pkts} = get_if_rx($i);
                $$counters{$i}{tx_pkts} = get_if_tx($i);
        }
}

sub verify_counters {
	my (%c1, %c2, %delta);
        my $errors = 0;
        foreach my $i (keys %c1) {
                if ($c1{$i}{rx_pkts} + $delta{$i}{rx_pkts} != $c2{$i}{rx_pkts}) {
                        $errors++;
                        print "rx_pkts comparison failed for interface $i, please fix\n";
                }
                if ($c1{$i}{tx_pkts} + $delta{$i}{tx_pkts} != $c2{$i}{tx_pkts}) {
		        $errors++;
                        print "tx_init + tx_pkts != tx_final for interface $i, please fix\n";
                }
        }
        return $errors;
}

sub setup_kmod {
	my $isNF2 = shift;
	
        # ensure all interfaces use an address
        for (my $i = 1; $i <= 4; $i++) {
        	my $iface = nftest_get_iface("eth$i");
                `/sbin/ifconfig $iface 192.168.$i.1`;
        }

        # verify kernel module not loaded
        my $of_kmod_loaded = `lsmod | grep openflow`;
        if ($of_kmod_loaded ne "") {
        	print "$of_kmod_loaded\n";
            print "openflow kernel module already loaded... please fix!\n";
            exit 1;
        }
        
        # verify controller not already running
        my $controller_loaded = `ps -A | grep controller`;
        if ($controller_loaded ne "") {
            print "controller already loaded... please remove and try again!\n";
            exit 1;
        }

        my $openflow_dir=$ENV{OF_ROOT};

        # create openflow switch on four ports
        `insmod ${openflow_dir}/datapath/linux-2.6/openflow_mod.ko`;
		
		# If we are using the NetFPGA add the hardware kernel module
		if ($isNF2) {
	        `insmod ${openflow_dir}/${nf2_kernel_module_path}/${nf2_kernel_module_name}`;
		}
        `dpctl adddp 0`;

        for (my $i = 5; $i <= 8; $i++) {
        	my $iface = nftest_get_iface("eth$i");
            `dpctl addif 0 $iface`;
        }
}

sub teardown_kmod {
	my $isNF2 = shift;

	# check that we're root?
	my $who = `whoami`;
	if (trim($who) ne 'root') { die "must be root\n"; }
	
	# check if openflow kernel module loaded
	my $of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ($of_kmod_loaded eq "") { die "nothing to do, exiting\n"; } 
	
	print "tearing down interfaces and datapaths\n";
	
	# remove interfaces from openflow
	for (my $i = 5; $i <= 8; $i++) {
		my $iface = nftest_get_iface("eth$i");
		`dpctl delif 0 $iface`;
	}

	`dpctl deldp 0`;
	
	# tear down the NF2 module if necessary
	if ($isNF2) {
		my $of_hw_kmod_removed = `rmmod ${nf2_kernel_module_name}`;
		if ($of_hw_kmod_removed ne "") {
			die "failed to remove hardware kernel module... please fix!\n";
		}
	}

	my $of_kmod_removed = `rmmod openflow_mod`;
	if ($of_kmod_removed ne "") {
		die "failed to remove kernel module... please fix!\n";
	}
	
	$of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ($of_kmod_loaded ne "") {
		die "failed to remove kernel module... please fix!\n";
	}

	exit 0;
}

sub compare {
	my ($test, $val, $op, $expected) = @_;
	my $success = eval "$val $op $expected" ? 1 : 0;
	if (!$success) { die "$test: error $val not $op $expected\n"; }
}

sub createControllerSocket {
	my ($host) = @_;
	my $sock = new IO::Socket::INET ( 
 		LocalHost => $host,
        	LocalPort => '975',
        	Proto => 'tcp',
        	Listen => 1,
        	Reuse => 1
	);
	die "Could not create socket: $!\n" unless $sock;
	return $sock;
}

sub process_command_line() {
	my %options = ();
	GetOptions(\%options, "map=s");
	
	# Process the mappings if specified
	if (defined($options{'map'})) {
		nftest_process_iface_map($options{'map'});
	}
	
	return %options;
}

sub run_learning_switch_test {
	my %options = process_command_line();

	# test is a function pointer
	my ($test) = @_;

	my ( %init_counters, %final_counters, %delta );

	my $pid;

	# Fork off a process for controller
	if ( !( $pid = fork ) ) {

		# Run controller from this process
		exec "controller", "-v", "nl:0";
		die "Failed to launch controller: $!";
	}
	else {
		my $exitCode = 1;
		try {

			# Run control from this process
			print "added controller...\n";

			# Wait for controller to load
			sleep(1);

			# Launch PCAP listenting interface
			nftest_init( \@ARGV, \@interfaces, );
			nftest_start( \@interfaces, );

			save_counters( \%init_counters );

			# Run test
			my %delta = &$test();

			# sleep as long as needed for the test to finish
			sleep 0.5;
		
			# check counter values
			save_counters( \%final_counters );
			my $total_errors = verify_counters( %init_counters, %final_counters, %delta );

			#print "about to nftest_finish()\n";
			my $unmatched = nftest_finish();

			print "Checking pkt errors\n";
			$total_errors += nftest_print_errors($unmatched);

			if ( $total_errors == 0 ) {
				print "SUCCESS!\n";
				$exitCode = 0;
			}
			else {
				print "FAIL: $total_errors errors\n";
				$exitCode = 1;
			}

		  }
		  catch Error with {

			# Catch and print any errors that occurred during control processing
			my $ex = shift;
			if ($ex) {
				print $ex->stringify();
			}
		  }
		  finally {

			# Ensure controller killed even if we have an error
			kill 9, $pid;

			# Exit with the resulting exit code
			exit($exitCode);
		  };
	}
}

sub do_hello_sequence {
	
	my ($ofp, $sock) = @_;
	
	my $hdr_args_control = {
		version => 1,
		type    => $enums{'OFPT_CONTROL_HELLO'},
		length  => 16,                             # should generate automatically!
		xid     => 0x00000000
	};
	my $control_hello_args = {
		header        => $hdr_args_control,
		version       => 1,                # arbitrary, not sure what this should be
		flags         => 1,                # ensure flow expiration sent!
		miss_send_len => $miss_send_len
	};
	my $control_hello = $ofp->pack( 'ofp_control_hello', $control_hello_args );

	# Send 'control_hello' message
	print $sock $control_hello;

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
	#print "received message after control hello\n";
	
	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_data_hello') + 4 * $ofp->sizeof('ofp_phy_port');
	# should probably account for the expected 4 ports' info
	compare ("msg size", length($recvd_mesg), '==', $expected_size);

	my $msg = $ofp->unpack('ofp_data_hello', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_DATA_HELLO'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);
}

sub run_black_box_test {
	my %options = process_command_line();
	
	# test is a function pointer
	my ($test) = @_;
	
	my $sock = createControllerSocket('localhost');
	
	my $pid;
	
	my $total_errors = 1;
	
	# Fork off the "controller" server
	if ( !( $pid = fork ) ) {
	
		# Wait for controller to setup socket
		sleep .1;
	
		# Spawn secchan process
		exec "secchan", "nl:0", "tcp:127.0.0.1";
		die "Failed to launch secchan: $!";
	}
	else {
		my $total_errors = 0;
		try {
	
			# Wait for secchan to connect
			my $new_sock = $sock->accept();		
	
			# Launch PCAP listenting interface
			nftest_init( \@ARGV, \@interfaces, );
			nftest_start( \@interfaces, );
	
			#if ($ofp) { print "ofp not null\n"; } else { print "ofp null\n"; }
			do_hello_sequence($ofp, $new_sock);
	
			&$test($new_sock, %options);
			
			# Sleep as long as needed for the test to finish
			sleep 0.5;
		}
		catch Error with {
	
			# Catch and print any errors that occurred during control processing
			my $ex = shift;
			if ($ex) {
				print $ex->stringify();
			}
			$total_errors = 1;
		}
		finally {

			close($sock);

			# Kill secchan process
			`killall secchan`;

			my $unmatched = nftest_finish();
			print "Checking pkt errors\n";
			$total_errors += nftest_print_errors($unmatched); 
	
			# if no errors earlier, and packets match, then success
			my $exitCode;
			if ( $total_errors == 0 ) {
				print "SUCCESS!\n";
				$exitCode = 0;
			}
			else {
				print "FAIL: $total_errors errors\n";
				$exitCode = 1;
			}
			
			exit($exitCode);
		};
	}
}

sub create_flow_mod_from_udp {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards ) = @_;

	my $flow_mod_pkt;

	$flow_mod_pkt = create_flow_mod_from_udp_action ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, 'OFPFC_ADD');

	return $flow_mod_pkt;
}

sub create_flow_mod_from_udp_action {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, $mod_type ) = @_;

	if ( $mod_type ne 'OFPFC_ADD' && $mod_type ne 'OFPFC_DELETE' && $mod_type ne 'OFPFC_DELETE_STRICT' ){
		die "Undefined flow mod type: $mod_type\n";
	}

	my $hdr_args = {
		version => 1,
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'),
		xid     => 0x0000000
	};

	# might be cleaner to convert the exported colon-hex MAC addrs
	#print ${$udp_pkt->{Ethernet_hdr}}->SA . "\n";
	#print ${$test_pkt->{Ethernet_hdr}}->SA . "\n";
	my $ref_to_eth_hdr = ( $udp_pkt->{'Ethernet_hdr'} );
	my $ref_to_ip_hdr  = ( $udp_pkt->{'IP_hdr'} );

	# pointer to array
	my $eth_hdr_bytes = $$ref_to_eth_hdr->{'bytes'};
	my $ip_hdr_bytes  = $$ref_to_ip_hdr->{'bytes'};
	my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
	my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

	my @src_ip_subarray = @{$ip_hdr_bytes}[ 12 .. 15 ];
	my @dst_ip_subarray = @{$ip_hdr_bytes}[ 16 .. 19 ];

	my $src_ip =
	  ( ( 2**24 ) * $src_ip_subarray[0] + ( 2**16 ) * $src_ip_subarray[1] +
		  ( 2**8 ) * $src_ip_subarray[2] + $src_ip_subarray[3] );

	my $dst_ip =
	  ( ( 2**24 ) * $dst_ip_subarray[0] + ( 2**16 ) * $dst_ip_subarray[1] +
		  ( 2**8 ) * $dst_ip_subarray[2] + $dst_ip_subarray[3] );

	my $match_args = {
		wildcards => $wildcards,
		in_port   => $in_port,
		dl_src    => \@src_mac_subarray,
		dl_dst    => \@dst_mac_subarray,
		dl_vlan   => 0xffff,
		dl_type   => 0x0800,
		nw_src    => $src_ip,
		nw_dst    => $dst_ip,
		nw_proto  => 17,                                  #udp
		tp_src    => ${ $udp_pkt->{UDP_pdu} }->SrcPort,
		tp_dst    => ${ $udp_pkt->{UDP_pdu} }->DstPort
	};

	my $action_output_args = {
		max_len => 0,                                     # send entire packet
		port    => $out_port
	};
	print "My Out Port: ${out_port}\n";

	my $action_args = {
		type => $enums{'OFPAT_OUTPUT'},
		arg  => { output => $action_output_args }
	};
	my $action = $ofp->pack( 'ofp_action', $action_args );

	my $flow_mod_args = {
		header    => $hdr_args,
		match     => $match_args,
#		command   => $enums{$mod_type},
		command   => $enums{"$mod_type"},
		max_idle  => $max_idle,
		buffer_id => 0x0000,
		group_id  => 0
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $flow_mod_pkt = $flow_mod . $action;

	return $flow_mod_pkt;
}

sub wait_for_flow_expired {
	
	my ($ofp, $sock, $pkt_len, $pkt_total) = @_;
	
	wait_for_flow_expired_size ($ofp, $sock, $pkt_len, $pkt_total, 1512);

}

sub wait_for_flow_expired_one {

	my ( $ofp, $sock, $pkt_len, $pkt_total ) = @_;

	wait_for_flow_expired_size ($ofp, $sock, $pkt_len, $pkt_total, $ofp->sizeof('ofp_flow_expired'));
}

sub wait_for_flow_expired_total_bytes {
	my ($ofp, $sock, $bytes, $pkt_total, $read_size_) = @_;
 	my $read_size;

	if (defined $read_size_ ){
		$read_size = $read_size_;
	}else{
		$read_size = 1512;
	}

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $read_size)
	  || die "Failed to receive message: $!";

	#print HexDump ($recvd_mesg);

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_expired');
	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_expired', $recvd_mesg );

	#print Dumper($msg);

	# Verify fields
	compare( "header version", $$msg{'header'}{'version'}, '==', 1 );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_EXPIRED'} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "byte_count",     $$msg{'byte_count'},        '==', $bytes );
	compare( "packet_count",   $$msg{'packet_count'},      '==', $pkt_total );
}

sub wait_for_flow_expired_size {
# can specify the reading size from socket (by the last argument, $read_size_)

	my ( $ofp, $sock, $pkt_len, $pkt_total, $read_size_ ) = @_;
	wait_for_flow_expired_total_bytes($ofp, $sock, ($pkt_len * $pkt_total), $pkt_total, $read_size_);
}
	
	
sub wait_for_one_packet_in {
# wait for a packet which arrives via socket, and verify it is the expected packet
# $sock: socket
# $pkt_len: packet length of the expected packet to receive
# $pkt : expected packet to receive

	my ( $ofp, $sock, $pkt_len, $pkt ) = @_;

	my $pkt_in_msg_size;  # read size from socket
	if ( $pkt_len < $miss_send_len ) {  
	    # Due to padding, the size of ofp_packet_in header is $ofp->sizeof('ofp_packet_in')-2
	    $pkt_in_msg_size = ($ofp->sizeof('ofp_packet_in')-2) + $pkt_len;
	}else {
		$pkt_in_msg_size = ($ofp->sizeof('ofp_packet_in')-2) + $miss_send_len;
	}

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $pkt_in_msg_size )
	  || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $pkt_in_msg_size;
	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

#	print Dumper($msg);

	# Verify fields
	compare( "header version", $$msg{'header'}{'version'}, '==', 1 );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_PACKET_IN'} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "header length",  $$msg{'total_len'},         '==', $pkt_len );

	my $recvd_pkt_data = substr ($recvd_mesg, $ofp->offsetof('ofp_packet_in', 'data'));

#	print "packet expecting\n";
#	print HexDump ($pkt);
#	print "packet received\n";
#	print HexDump ($recvd_pkt_data);

        if ($recvd_pkt_data ne $pkt) {
	    die "ERROR: received packet data didn't match the expecting packet\n";
        }
}


# Always end library in 1
1;
