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
use Socket qw(:all);
use IO::Socket;
#use IO::Socket::INET;
use Data::HexDump;
use Time::HiRes qw(sleep gettimeofday tv_interval usleep); 

@ISA    = ('Exporter');
@EXPORT = qw(
  &trim
  &send_and_count
  &expect_and_count
  &save_counters
  &verify_counters
  &setup_pcap_interfaces
  &setup_kmod
  &setup_user
  &setup_NF2
  &teardown_kmod
  &teardown_user
  &teardown_NF2
  &compare
  &create_controller_socket
  &run_learning_switch_test
  &do_hello_sequence
  &get_switch_features
  &get_config
  &set_config
  &run_black_box_test
  &create_flow_mod_from_udp
  &create_flow_mod_from_udp_action
  &wait_for_flow_expired
  &wait_for_flow_expired_all
  &wait_for_flow_expired_readone
  &wait_for_flow_expired_readsize
  &wait_for_flow_expired_total_bytes
  &wait_for_one_packet_in
  &verify_header
  &get_of_ver
  &get_of_port
  &get_of_miss_send_len_default
  &enable_flow_expirations
  &get_default_black_box_pkt
  &get_default_black_box_pkt_len
  &for_all_port_pairs
  &for_all_ports
  &for_all_wildcards
  &forward_simple
  &forward_simple_icmp
  &get_default_black_box_pkt_len_icmp
  &create_flow_mod_from_icmp_action
  &create_flow_mod_from_icmp
  &wait_for_two_flow_expired
);

my $nf2_kernel_module_path        = 'datapath/linux-2.6';
my $nf2_kernel_module_name_no_ext = 'hwtable_nf2_mod';
my $nf2_kernel_module_name        = $nf2_kernel_module_name_no_ext . '.ko';
my $openflow_dir                  = $ENV{OF_ROOT};

if (! -e "$openflow_dir/include/openflow/openflow.h") {
	die "please set OF_ROOT in path so that OFUtil.pm can extract constants"
}

sub get_define {
	my $val = shift;
	my $retval = `grep \"#define $val \" \$OF_ROOT/include/openflow/openflow.h | awk '{print \$3}'`;
	chomp $retval;
	return $retval;
}

# extract #defines from openflow.h
my $of_ver = get_define('OFP_VERSION');
my $of_port = get_define('OFP_TCP_PORT');
my $of_miss_send_len = get_define('OFP_DEFAULT_MISS_SEND_LEN');

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ( "eth1", "eth2", "eth3", "eth4" );

##############################################################

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub get_if_rx {
	my $interface = shift;
	return
`/sbin/ifconfig $interface | grep \'RX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;
}

sub get_if_tx {
	my $interface = shift;
	return
`/sbin/ifconfig $interface | grep \'TX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;
}

sub send_and_count {
	my ( $interface, $pkt, $counters ) = @_;
	nftest_send( $interface, $pkt );
	$$counters{$interface}{tx_pkts}++;
}

sub expect_and_count {
	my ( $interface, $pkt, $counters ) = @_;
	nftest_expect( $interface, $pkt );
	$$counters{$interface}{rx_pkts}++;
}

sub save_counters {
	my $counters = @_;
	foreach my $i ( keys %counters ) {
		$$counters{$i}{rx_pkts} = get_if_rx($i);
		$$counters{$i}{tx_pkts} = get_if_tx($i);
	}
}

sub verify_counters {
	my ( %c1, %c2, %delta );
	my $errors = 0;
	foreach my $i ( keys %c1 ) {
		if ( $c1{$i}{rx_pkts} + $delta{$i}{rx_pkts} != $c2{$i}{rx_pkts} ) {
			$errors++;
			print "rx_pkts comparison failed for interface $i, please fix\n";
		}
		if ( $c1{$i}{tx_pkts} + $delta{$i}{tx_pkts} != $c2{$i}{tx_pkts} ) {
			$errors++;
			print "tx_init + tx_pkts != tx_final for interface $i, please fix\n";
		}
	}
	return $errors;
}

sub setup_pcap_interfaces {

	# ensure all interfaces use an address
	for ( my $i = 1 ; $i <= 4 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`/sbin/ifconfig $iface 192.168.10$i.1`;
	}
}

sub setup_kmod {

	setup_pcap_interfaces();

	# verify kernel module not loaded
	my $of_kmod_loaded = `lsmod | grep openflow`;
	if ( $of_kmod_loaded ne "" ) {
		print "openflow kernel module already loaded... please fix!\n";
		exit 1;
	}

	# verify controller not already running
	my $controller_loaded = `ps -A | grep controller`;
	if ( $controller_loaded ne "" ) {
		print "controller already loaded... please remove and try again!\n";
		exit 1;
	}

	my $openflow_dir = $ENV{'OF_ROOT'};

	# create openflow switch on four ports
	`insmod ${openflow_dir}/datapath/linux-2.6/openflow_mod.ko`;

	`${openflow_dir}/utilities/dpctl adddp nl:0`;

	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`${openflow_dir}/utilities/dpctl addif nl:0 $iface`;
	}

	system("${openflow_dir}/secchan/secchan --inactivity-probe=999999 nl:0 tcp:127.0.0.1 &");
}

sub setup_NF2 {

	setup_pcap_interfaces();

	# verify kernel module not loaded
	my $of_kmod_loaded = `lsmod | grep openflow`;
	if ( $of_kmod_loaded ne "" ) {
		print "$of_kmod_loaded\n";
		print "openflow kernel module already loaded... please fix!\n";
		exit 1;
	}

	# verify controller not already running
	my $controller_loaded = `ps -A | grep controller`;
	if ( $controller_loaded ne "" ) {
		print "controller already loaded... please remove and try again!\n";
		exit 1;
	}
	
    # load the openflow bitfile on the NetFPGA
	system("nf2_download ${openflow_dir}/datapath/hwtable_nf2/openflow_switch.bit");

    # turn on phy(0-3) interrupt mask
    # in order to avoid asynchronous port_mod_change message
        `regwrite 0x04c006c 0xffff`;
        `regwrite 0x04c00ec 0xffff`;
        `regwrite 0x04c016c 0xffff`;
        `regwrite 0x04c01ec 0xffff`;

	# create openflow switch on four ports
	`insmod ${openflow_dir}/datapath/linux-2.6/openflow_mod.ko`;

	# add the hardware kernel module
	`insmod ${openflow_dir}/${nf2_kernel_module_path}/${nf2_kernel_module_name}`;

	`${openflow_dir}/utilities/dpctl adddp nl:0`;
    print "added datapath\n";

	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		print "${openflow_dir}/utilities/dpctl addif nl:0 $iface";
		`${openflow_dir}/utilities/dpctl addif nl:0 $iface`;
        print "added interface\n";
	}

	system("${openflow_dir}/secchan/secchan --inactivity-probe=999999 nl:0 tcp:127.0.0.1 &");
}

sub setup_user {

	setup_pcap_interfaces();

	# create openflow switch on four ports
	my $if_string = '';
	for ( my $i = 5 ; $i <= 7 ; $i++ ) {
		$if_string .= nftest_get_iface("eth$i") . ',';
	}
	$if_string .= nftest_get_iface("eth8");
	print "about to create switch tcp:127.0.0.1 -i $if_string \& \n";
	system("${openflow_dir}/switch/switch tcp:127.0.0.1 -i $if_string \&");
}

sub teardown_kmod {

	# check that we're root?
	my $who = `whoami`;
	if ( trim($who) ne 'root' ) { die "must be root\n"; }

	`killall secchan`;

	# check if openflow kernel module loaded
	my $of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ( $of_kmod_loaded eq "" ) { exit 0; }

	print "tearing down interfaces and datapaths\n";

	# remove interfaces from openflow
	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`${openflow_dir}/utilities/dpctl delif nl:0 $iface`;
	}

	`${openflow_dir}/utilities/dpctl deldp nl:0`;

	my $of_kmod_removed = `rmmod openflow_mod`;
	if ( $of_kmod_removed ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	$of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ( $of_kmod_loaded ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	exit 0;
}

sub teardown_NF2 {

	# check that we're root?
	my $who = `whoami`;
	if ( trim($who) ne 'root' ) { die "must be root\n"; }

	`killall secchan`;

	# check if openflow kernel module loaded
	my $of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ( $of_kmod_loaded eq "" ) { exit 0; }

	print "tearing down interfaces and datapaths\n";

	# remove interfaces from openflow
	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`${openflow_dir}/utilities/dpctl delif nl:0 $iface`;
	}

	`${openflow_dir}/utilities/dpctl deldp nl:0`;

	# tear down the NF2 module
	my $of_hw_kmod_removed = `rmmod ${nf2_kernel_module_name_no_ext}`;
	if ( $of_hw_kmod_removed ne "" ) {
		die "failed to remove hardware kernel module... please fix!\n";
	}

	my $of_kmod_removed = `rmmod openflow_mod`;
	if ( $of_kmod_removed ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	$of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ( $of_kmod_loaded ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	exit 0;
}

sub teardown_user {

	# check that we're root?
	my $who = `whoami`;
	if ( trim($who) ne 'root' ) { die "must be root\n"; }

	`killall switch`;

	exit 0;
}

sub compare {
	my ( $test, $val, $op, $expected ) = @_;
	my $success = eval "$val $op $expected" ? 1 : 0;
	if ( !$success ) { die "$test: error $val not $op $expected\n"; }
}

sub create_controller_socket {
	my ($host, $port) = @_;
	print "about to make socket\n";
	my $sock = new IO::Socket::INET(
		LocalHost => $host,
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 1,
		Reuse     => 1
	);
	die "Could not create socket: $!\n" unless $sock;
	# Don't hold to data - Jean II
	$sock->sockopt(TCP_NODELAY, 1) or die "\$sock->sockopt NODELAY, 1: $! ($^E)";
	$sock->autoflush();
	# It also tried $| = 1; before the print but it did not help - Jean II
	print "made socket\n";
	return $sock;
}

# This does not look like it's used ? - Jean II
sub process_command_line() {
	my %options = ();

	GetOptions( \%options, "map=s" );

	# Process the mappings if specified
	if ( defined( $options{'map'} ) ) {
		nftest_process_iface_map( $options{'map'} );
	} else {
		# If not specified on command line, use enviroment variable
		# Jean II
		if (defined($ENV{'OFT_MAP_ETH'})) {
			nftest_process_iface_map( $ENV{OFT_MAP_ETH} );
		}
	}

	return %options;
}

sub run_learning_switch_test {

	# test is a function pointer
	my ( $test_ref, $argv_ref) = @_;

	my %options = nftest_init( $argv_ref, \@interfaces, );

	my ( %init_counters, %final_counters, %delta );

	my $pid;

	# Fork off a process for controller
	if ( !( $pid = fork ) ) {

		# Run controller from this process
		exec "$ENV{'OF_ROOT'}/controller/controller", "ptcp:";
		die "Failed to launch controller: $!";
	}
	else {
		my $exitCode = 1;
		try {

			# Run control from this process
			print "added controller...\n";

			# Wait for controller to load
			sleep(1);

			nftest_start( \@interfaces, );

			save_counters( \%init_counters );

			# Run test
			my %delta = &$test_ref();

			# sleep as long as needed for the test to finish
			sleep 5;

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

	my ( $ofp, $sock ) = @_;

	my $hdr_args_hello = {
		version => $of_ver,
		type 	=> $enums{'OFPT_HELLO'},
		length  => $ofp->sizeof('ofp_header'),
		xid 	=> 0
	};
	my $hello = $ofp->pack( 'ofp_header', $hdr_args_hello);
	
	# Send 'hello' message
	syswrite( $sock, $hello );

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	#print "received message after features request\n";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_header');
#	my $expected_size = $ofp->sizeof('ofp_switch_features') + 4 * $ofp->sizeof('ofp_phy_port');

	# should probably account for the expected 4 ports' info
	# !!! disabled until we can inspect these
	#compare( "msg size", length($recvd_mesg), '==', $expected_size );

	#my $msg = $ofp->unpack( 'ofp_switch_features', $recvd_mesg );
	my $msg = $ofp->unpack( 'ofp_hello', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header( $msg, 'OFPT_HELLO', $msg_size );
	
	print "received Hello\n";
}

sub get_switch_features {

	my ( $ofp, $sock ) = @_;

	my $hdr_args_features_request = {
		version => $of_ver,
		type    => $enums{'OFPT_FEATURES_REQUEST'},
		length  => $ofp->sizeof('ofp_header'),        # should generate automatically!
		xid     => 0x00000000
	};
	my $features_request = $ofp->pack( 'ofp_header', $hdr_args_features_request );

	# Send 'features_request' message
	syswrite( $sock, $features_request );

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	#print "received message after features request\n";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	#my $expected_size = $ofp->sizeof('ofp_switch_config');

	#compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_switch_features', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify header fields
	verify_header( $msg, 'OFPT_FEATURES_REPLY', $msg_size );

	return $msg;
}

sub get_config {

	my ( $ofp, $sock ) = @_;

	my $hdr_args_get_config_request = {
		version => $of_ver,
		type    => $enums{'OFPT_GET_CONFIG_REQUEST'},
		length  => $ofp->sizeof('ofp_header'),
		xid     => 0x0000000
	};

	my $get_config_request = $ofp->pack( 'ofp_header', $hdr_args_get_config_request );

	# Send 'get_config_request' message
	syswrite( $sock, $get_config_request );

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	#print "received message after features request\n";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_switch_config');

	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_switch_config', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify header fields
	verify_header( $msg, 'OFPT_GET_CONFIG_REPLY', $msg_size );

	return $msg;
}

sub set_config {

	my ( $ofp, $sock, $flags, $miss_send_len ) = @_;

	my $hdr_args = {
		version => $of_ver,
		type    => $enums{'OFPT_SET_CONFIG'},
		length  => $ofp->sizeof('ofp_switch_config'),
		xid     => 0x0000000
	};

	my $set_config_args = {
		header        => $hdr_args,
		flags         => $flags,
		miss_send_len => $miss_send_len
	};

	my $set_config = $ofp->pack( 'ofp_switch_config', $set_config_args );

	# Send 'get_config_request' message
	syswrite( $sock, $set_config );
}

sub run_black_box_test {
	
	my ( $test_ref, $argv_ref ) = @_;

	my %options = nftest_init( $argv_ref, \@interfaces, );

	my $host = 'localhost';
	my $port = $of_port;
	# extract host and port from controller string if passed in
	if (defined $options{'controller'}) {
		# Assume fully qualified string : tcp:<controller>:<port>
		# Jean II
		($proto, $host, $port) = split(/:/,$options{'controller'});
		# Check for string missing the protocol - Jean II
		if ( ! defined ($port) ) {
			$proto = "tcp";
			($host, $port) = split(/:/,$options{'controller'});
		}
	}
	#!!!
	print "using host $host and port $port\n";

	$sock = create_controller_socket($host, $port);

	my $total_errors = 0;
	try {

		# Wait for secchan to connect
		print "waiting for secchan to connect\n";
		my $new_sock = $sock->accept();

		do_hello_sequence( $ofp, $new_sock );

		# Launch PCAP listenting interface
		nftest_start( \@interfaces );

		&$test_ref( $new_sock, \%options );

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

sub create_flow_mod_from_udp {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards ) = @_;

	my $flow_mod_pkt;

	$flow_mod_pkt =
	  create_flow_mod_from_udp_action( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards,
		'OFPFC_ADD' );

	return $flow_mod_pkt;
}

sub create_flow_mod_from_udp_action {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, $mod_type ) = @_;

	if (   $mod_type ne 'drop' 
		&& $mod_type ne 'OFPFC_ADD'
		&& $mod_type ne 'OFPFC_DELETE'
		&& $mod_type ne 'OFPFC_DELETE_STRICT' )
	{
		die "Undefined flow mod type: $mod_type\n";
	}

	my $length;
	if ($mod_type eq 'drop') {
		$length = $ofp->sizeof('ofp_flow_mod') + 0; # Careful, no actions for drop - Jean II
	} else {
		$length = $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action_output');		
	}

	my $hdr_args = {
		version => $of_ver,
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $length,
		xid     => 0x0000000
	};

	# might be cleaner to convert the exported colon-hex MAC addrs
	#print ${$udp_pkt->{Ethernet_hdr}}->SA . "\n";
	#print ${$test_pkt->{Ethernet_hdr}}->SA . "\n";
	my $ref_to_eth_hdr = ( $udp_pkt->{'Ethernet_hdr'} );
	my $ref_to_ip_hdr  = ( $udp_pkt->{'IP_hdr'} );

	# pointer to array
	my $eth_hdr_bytes    = $$ref_to_eth_hdr->{'bytes'};
	my $ip_hdr_bytes     = $$ref_to_ip_hdr->{'bytes'};
	my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
	my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

	my @src_ip_subarray = @{$ip_hdr_bytes}[ 12 .. 15 ];
	my @dst_ip_subarray = @{$ip_hdr_bytes}[ 16 .. 19 ];

	my $src_ip =
	  ( ( 2**24 ) * $src_ip_subarray[0] +
		  ( 2**16 ) * $src_ip_subarray[1] +
		  ( 2**8 ) * $src_ip_subarray[2] +
		  $src_ip_subarray[3] );

	my $dst_ip =
	  ( ( 2**24 ) * $dst_ip_subarray[0] +
		  ( 2**16 ) * $dst_ip_subarray[1] +
		  ( 2**8 ) * $dst_ip_subarray[2] +
		  $dst_ip_subarray[3] );

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

	my $action_output_args;
	my $action_output;
	
	# no action for drops
	if ($mod_type ne 'drop') {
		$action_output_args = {
			type => $enums{'OFPAT_OUTPUT'},
			len => $ofp->sizeof('ofp_action_output'),
			port => $out_port,
			max_len => 0,                                     # send entire packet	
		};
		$action_output = $ofp->pack( 'ofp_action_output', $action_output_args );
	}
	
	my $flow_mod_args = {
		header => $hdr_args,
		match  => $match_args,

		#		command   => $enums{$mod_type},
		command   => $enums{"$mod_type"},
		idle_timeout  => $max_idle,
		hard_timeout  => $max_idle,
		priority => 0,
		buffer_id => -1,
		out_port => $enums{'OFPP_NONE'}
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $flow_mod_pkt = $flow_mod . $action_output;

	return $flow_mod_pkt;
}

sub wait_for_flow_expired {

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
}

sub wait_for_flow_expired_all {

	my ( $ofp, $sock, $options_ref ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref, $$options_ref{'pkt_len'}, $$options_ref{'pkt_total'} );
}

sub wait_for_flow_expired_readone {

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref, $pkt_len, $pkt_total,
		$ofp->sizeof('ofp_flow_expired') );
}

sub wait_for_flow_expired_readsize {

	# can specify the reading size from socket (by the last argument, $read_size_)

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total, $read_size_ ) = @_;
	wait_for_flow_expired_total_bytes( $ofp, $sock, $options_ref, ( $pkt_len * $pkt_total ),
		$pkt_total, $read_size_ );
}

sub wait_for_flow_expired_total_bytes {
	my ( $ofp, $sock, $options_ref, $bytes, $pkt_total, $read_size_ ) = @_;
	my $read_size;

	if ( defined $read_size_ ) {
		$read_size = $read_size_;
	} else {
		$read_size = 1512;
	}

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $read_size )
	  || die "Failed to receive ofp_flow_expired message: $!";

	#print HexDump ($recvd_mesg);

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_expired');
	compare( "ofp_flow_expired msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_expired', $recvd_mesg );

	#print Dumper($msg);

	# Verify fields
	compare( "ofp_flow_expired header version", $$msg{'header'}{'version'}, '==', $of_ver );
	compare( "ofp_flow_expired header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_EXPIRED'} );
	compare( "ofp_flow_expired header length",  $$msg{'header'}{'length'},  '==', $msg_size );

	# Disable for platforms that don't have byte counts... - Jean II
	if ( not defined( $$options_ref{'ignore_byte_count'} ) ) {
	    compare( "ofp_flow_expired byte_count",     $$msg{'byte_count'},        '==', $bytes );
	}
	compare( "ofp_flow_expired packet_count",   $$msg{'packet_count'},      '==', $pkt_total );
}

sub wait_for_one_packet_in {

	# wait for a packet which arrives via socket, and verify it is the expected packet
	# $sock: socket
	# $pkt_len: packet length of the expected packet to receive
	# $pkt : expected packet to receive

	my ( $ofp, $sock, $pkt_len, $pkt ) = @_;

	my $pkt_in_msg_size;    # read size from socket
	if ( $pkt_len < $of_miss_send_len ) {

		# Due to padding, the size of ofp_packet_in header is $ofp->sizeof('ofp_packet_in')-2
		$pkt_in_msg_size = ( $ofp->sizeof('ofp_packet_in') - 2 ) + $pkt_len;
	}
	else {
		$pkt_in_msg_size = ( $ofp->sizeof('ofp_packet_in') - 2 ) + $of_miss_send_len;
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
	compare( "header version", $$msg{'header'}{'version'}, '==', $of_ver );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_PACKET_IN'} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "header length",  $$msg{'total_len'},         '==', $pkt_len );

	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );

	#	print "packet expecting\n";
	#	print HexDump ($pkt);
	#	print "packet received\n";
	#	print HexDump ($recvd_pkt_data);

	if ( $recvd_pkt_data ne $pkt ) {
		die "ERROR: received packet data didn't match the expecting packet\n";
	}
}

sub verify_header {

	my ( $msg, $ofpt, $msg_size ) = @_;

	compare( "header version", $$msg{'header'}{'version'}, '==', $of_ver );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{$ofpt} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
}

sub get_of_ver {
	return $of_ver;
}

sub get_of_port {
	return $of_port;
}

sub get_of_miss_send_len_default {
	return $of_miss_send_len;
}

sub enable_flow_expirations {

	my ( $ofp, $sock ) = @_;

	my $flags         = 1;                       # OFPC_SEND_FLOW_EXP = 0x0001;
	my $miss_send_len = $of_miss_send_len;
	set_config( $ofp, $sock, $flags, $miss_send_len );
}

sub get_default_black_box_pkt {
	my ($in_port, $out_port) = @_; 

	return get_default_black_box_pkt_len($in_port, $out_port, 64);
}

sub get_default_black_box_pkt_len {
	my ($in_port, $out_port, $len) = @_; 

	my $pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port ),
		SA     => "00:00:00:00:00:0" . ( $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $len,
		src_port => 1,
		dst_port => 0
	};
	return new NF2::UDP_pkt(%$pkt_args);
}

sub for_all_port_pairs {

	my ( $ofp, $sock, $options_ref, $fcn_ref, $wc ) = @_;

    my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	# send from every port to every other port
	for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
		for ( my $j = 0 ; $j < $num_ports ; $j++ ) {
			if ( $i != $j ) {
				print "sending from port offset $i to $j\n";
				&$fcn_ref( $ofp, $sock, $options_ref, $i, $j, $wc);
			}
		}
	}
}

sub for_all_ports {

	my ( $ofp, $sock, $options_ref, $fcn_ref, $wc ) = @_;

    my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	# send from every port
	for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
		print "sending from port offset $i to (all port offsets but $i)\n";
		&$fcn_ref( $ofp, $sock, $options_ref, $i, -1, $wc);
	}
}

sub for_all_wildcards {

	my ( $ofp, $sock, $options_ref, $fcn_ref) = @_;

    my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	my %wildcards = (
		0x0001 => 'IN_PORT',
		#0x0002 => 'DL_VLAN', # currently fixed at 0xffff
		0x0004 => 'DL_SRC',
		0x0008 => 'DL_DST',
		#0x0010 => 'DL_TYPE', # currently fixed at 0x0800
		0x2000 => 'NW_SRC',
		0x80000 => 'NW_DST',
		#0x0080 => 'NW_PROTO', # currently fixed at 0x17
		0x0040 => 'TP_SRC',
		0x0080 => 'TP_DST',
	);

	# send from every port
	# uncomment below for a more complete test 
	my $i = 0;
	
	#for ( $i = 0 ; $i < $num_ports ; $i++ ) {

		my $j = ($i + 1) % 4;
		
		print "sending from $i to $j\n";
		
		for my $wc (sort keys %wildcards) {
			printf ("wildcards: 0x%04x ".$wildcards{$wc}."\n", $wc);
			&$fcn_ref( $ofp, $sock, $options_ref, $i, $j, $wc);
		}
	#}
}

sub forward_simple {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $wildcards, $type, $nowait ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port;
	
	if ($type eq 'all') {
		$out_port = $enums{'OFPP_ALL'};    # all physical ports except the input
	}
	elsif ($type eq 'controller') {
		$out_port = $enums{'OFPP_CONTROLLER'};	 #send to the secure channel		
	}
	else {
		$out_port = $out_port_offset + $$options_ref{'port_base'};		
	}

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );

	#print HexDump ( $test_pkt->packed );

	my $flow_mod_pkt;
	
	if ($type eq 'drop') {
		$flow_mod_pkt = create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards, 'drop' );
	} else {
		$flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards );
	}

	#print HexDump($flow_mod_pkt);
	#print Dumper($flow_mod_pkt);

	# Send 'flow_mod' message
	syswrite( $sock, $flow_mod_pkt );
	print "sent flow_mod message\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	nftest_send( "eth" . ($in_port_offset + 1), $test_pkt->packed );
	
	if ($type eq 'any' || $type eq 'port') {
		# expect single packet
		print "expect single packet\n";
		nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
	}
	elsif ($type eq 'all') {
		# expect packets on all other interfaces
		print "expect multiple packets\n";
		for ( my $k = 0 ; $k < $$options_ref{'num_ports'} ; $k++ ) {
			if ( $k != $in_port_offset ) {
				nftest_expect( "eth" . ( $k + 1), $test_pkt->packed );
			}
		}
	}
	elsif ($type eq 'controller') {
		# expect at controller
		
		my $recvd_mesg;
		sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
	
		# Inspect  message
		my $msg_size = length($recvd_mesg);
		my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt->packed );
		compare( "msg size", $msg_size, '==', $expected_size );
	
		my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );
	
		#print HexDump ($recvd_mesg);
		#print Dumper($msg);
	
		# Verify fields
		print "Verifying secchan message for packet sent in to eth" . ( $in_port + 1 ) . "\n";
	
		verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );
	
		compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
		compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
		compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );
	
		# verify packet was unchanged!
		my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
		if ( $recvd_pkt_data ne $test_pkt->packed ) {
			die "ERROR: sending from eth"
			  . ($in_port_offset + 1)
			  . " received packet data didn't match packet sent\n";
		}
			
	}
	elsif ($type eq 'drop') {
		# do nothing!
	}
	else {
		die "invalid input to forward_simple\n";
	}
	
	if (not defined($nowait)) {
		print "wait \n";
		wait_for_flow_expired_all( $ofp, $sock, $options_ref );	
	}
}


#Sub functions for ICMP handling tests

sub get_default_black_box_pkt_len_icmp {
        my ($in_port, $out_port, $len) = @_;

        my $pkt_args = {
                DA     => "00:00:00:00:00:0" . ( $out_port ),
                SA     => "00:00:00:00:00:0" . ( $in_port ),
                src_ip => "192.168.200." .     ( $in_port ),
                dst_ip => "192.168.201." .     ( $out_port ),
                ttl    => 64,
                len    => $len,
                src_port => 1,
                dst_port => 0
        };
        return new_icmp_test_pkt NF2::ICMP_pkt(%$pkt_args);
}

sub create_flow_mod_from_icmp {

        my ( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $wildcards, $fool ) = @_;

        my $flow_mod_pkt;

        $flow_mod_pkt =
          create_flow_mod_from_icmp_action( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $wildcards,
                'OFPFC_ADD', $fool );

        return $flow_mod_pkt;
}

sub create_flow_mod_from_icmp_action {

        my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, $mod_type, $fool ) = @_;

        if (   $mod_type ne 'OFPFC_ADD'
                && $mod_type ne 'OFPFC_DELETE'
                && $mod_type ne 'OFPFC_DELETE_STRICT' )
        {
                die "Undefined flow mod type: $mod_type\n";
        }

        my $hdr_args = {
                version => $of_ver,
                type    => $enums{'OFPT_FLOW_MOD'},
                length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action_output'),
                xid     => 0x0000000
        };

        # might be cleaner to convert the exported colon-hex MAC addrs
        #print ${$udp_pkt->{Ethernet_hdr}}->SA . "\n";
        #print ${$test_pkt->{Ethernet_hdr}}->SA . "\n";
        my $ref_to_eth_hdr = ( $udp_pkt->{'Ethernet_hdr'} );
        my $ref_to_ip_hdr  = ( $udp_pkt->{'IP_hdr'} );

        # pointer to array
        my $eth_hdr_bytes    = $$ref_to_eth_hdr->{'bytes'};
        my $ip_hdr_bytes     = $$ref_to_ip_hdr->{'bytes'};
        my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
        my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

        my @src_ip_subarray = @{$ip_hdr_bytes}[ 12 .. 15 ];
        my @dst_ip_subarray = @{$ip_hdr_bytes}[ 16 .. 19 ];

        my $src_ip =
          ( ( 2**24 ) * $src_ip_subarray[0] +
                  ( 2**16 ) * $src_ip_subarray[1] +
                  ( 2**8 ) * $src_ip_subarray[2] +
                  $src_ip_subarray[3] );

        my $dst_ip =
          ( ( 2**24 ) * $dst_ip_subarray[0] +
                  ( 2**16 ) * $dst_ip_subarray[1] +
                  ( 2**8 ) * $dst_ip_subarray[2] +
                  $dst_ip_subarray[3] );

        my $icmp_type;
        if ($fool == 1) {
                $icmp_type = ~(${ $udp_pkt->{ICMP_pdu} }->Type);
        } else {
                $icmp_type = (${ $udp_pkt->{ICMP_pdu} }->Type);
        }

        my $icmp_code = ${ $udp_pkt->{ICMP_pdu} }->Code;

        my $match_args = {
                wildcards => $wildcards,
                in_port   => $in_port,
                dl_src    => \@src_mac_subarray,
                dl_dst    => \@dst_mac_subarray,
                dl_vlan   => 0xffff,
                dl_type   => 0x0800,
                nw_src    => $src_ip,
                nw_dst    => $dst_ip,
                nw_proto  => 1,                                  #ICMP
                tp_src    => $icmp_type,
                tp_dst    => $icmp_code
        };

        my $action_output_args = {
                type => $enums{'OFPAT_OUTPUT'},
                len => $ofp->sizeof('ofp_action_output'),
                port => $out_port,
                max_len => 0,                                     # send entire packet
        };

        my $action_output = $ofp->pack( 'ofp_action_output', $action_output_args );

        my $flow_mod_args = {
                header => $hdr_args,
                match  => $match_args,

                #               command   => $enums{$mod_type},
                command   => $enums{"$mod_type"},
                idle_timeout  => $max_idle,
                hard_timeout  => $max_idle,
                priority => 0,
                buffer_id => -1,
                out_port => $enums{'OFPP_NONE'}
        };
        my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

        my $flow_mod_pkt = $flow_mod . $action_output;

        return $flow_mod_pkt;
}

sub forward_simple_icmp {

        my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $wildcards, $type, $fool, $nowait ) = @_;

        my $in_port = $in_port_offset + $$options_ref{'port_base'};
        my $out_port;

        my $fool_port = 0;
        my $flow_mod_pkt_fool;

        if ($type eq 'all') {
                $out_port = $enums{'OFPP_ALL'};    # all physical ports except the input
        }
        elsif ($type eq 'controller') {
                $out_port = $enums{'OFPP_CONTROLLER'};   #send to the secure channel
        }
        else {
                $out_port = $out_port_offset + $$options_ref{'port_base'};
        }

        if ($fool == 1) {
                $fool_port = ($out_port_offset + $$options_ref{'port_base'} + 1) % $$options_ref{'num_ports'};
                if ($fool_port == $in_port) {
                        $fool_port = ($out_port_offset + $$options_ref{'port_base'} + 2) % $$options_ref{'num_ports'};
                }
        }

        my $test_pkt = get_default_black_box_pkt_len_icmp( $in_port, $out_port, $$options_ref{'pkt_len'} );

        #print HexDump ( $test_pkt->packed );

        if (($fool == 1) && ($type eq 'port') && ($wildcards != 0x40)) {
                my $flow_mod_pkt_fool =
                  create_flow_mod_from_icmp( $ofp, $test_pkt, $in_port, $fool_port, $$options_ref{'max_idle'}, $wildcards, $fool );
                print HexDump($flow_mod_pkt_fool);
                #print Dumper($flow_mod_pkt_fool);
                # Send 'flow_mod' message
                print $sock $flow_mod_pkt_fool;
                print "sent flow_mod message\n";
                # Give OF switch time to process the flow mod
                usleep($$options_ref{'send_delay'});
        }

        my $flow_mod_pkt =
          create_flow_mod_from_icmp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards, 0 );

        #print HexDump($flow_mod_pkt);
        #print Dumper($flow_mod_pkt);

        # Send 'flow_mod' message
        print $sock $flow_mod_pkt;
        print "sent flow_mod message\n";

        # Give OF switch time to process the flow mod
        usleep($$options_ref{'send_delay'});

        nftest_send( "eth" . ($in_port_offset + 1), $test_pkt->packed );
        #print HexDump($test_pkt->packed);

        if ($type eq 'any' || $type eq 'port') {
                # expect single packet
                print "expect single packet\n";
                nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
        }
        elsif ($type eq 'all') {
                # expect packets on all other interfaces
                print "expect multiple packets\n";
                for ( my $k = 0 ; $k < $$options_ref{'num_ports'} ; $k++ ) {
                        if ( $k != $in_port_offset ) {
                                nftest_expect( "eth" . ( $k + 1), $test_pkt->packed );
                        }
                }
        }
        elsif ($type eq 'controller') {
                # expect at controller

                my $recvd_mesg;
                sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

                # Inspect  message
                my $msg_size = length($recvd_mesg);
                my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt->packed );
                compare( "msg size", $msg_size, '==', $expected_size );

                my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

                #print HexDump ($recvd_mesg);
                #print Dumper($msg);

                # Verify fields
                print "Verifying secchan message for packet sent in to eth" . ( $in_port + 1 ) . "\n";

                verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

                compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
                compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
                compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );

                # verify packet was unchanged!
                my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
                if ( $recvd_pkt_data ne $test_pkt->packed ) {
                        die "ERROR: sending from eth"
                          . ($in_port_offset + 1)
                          . " received packet data didn't match packet sent\n";
                }
        }
        else {
                die "invalid input to forward_simple_icmp\n";
        }

        if (not defined($nowait)) {
                print "wait \n";
		if ($fool == 1) {
                        print "wait for two flow exprired\n";
                        wait_for_two_flow_expired( $ofp, $sock, $$options_ref{'pkt_len'}, $$options_ref{'pkt_total'} );
                } else {
                        print "wait for flow expired\n";
                        wait_for_flow_expired( $ofp, $sock, $options_ref, $$options_ref{'pkt_len'}, $$options_ref{'pkt_total'} );
                }
        }
}

sub wait_for_two_flow_expired {

        my ( $ofp, $sock, $pkt_len, $pkt_total ) = @_;
        my $read_size = 1512;
        my $pkt_total_size = $pkt_len * $pkt_total;

        my $recvd_mesg;

        sysread( $sock, $recvd_mesg, $read_size )
          || die "Failed to receive message: $!";

        #print HexDump ($recvd_mesg);

        # Inspect  message
        my $msg_size      = length($recvd_mesg);
        my $expected_size = $ofp->sizeof('ofp_flow_expired');
        #compare( "msg size", length($recvd_mesg), '==', $expected_size );

        my $msg = $ofp->unpack( 'ofp_flow_expired', $recvd_mesg );

        #print Dumper($msg);

        # Verify fields
        #compare( "header version", $$msg{'header'}{'version'}, '==', $of_ver );
        #compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_EXPIRED'} );
        #compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
        #compare( "byte_count",     $$msg{'byte_count'},        '==', $bytes );
        #compare( "packet_count",   $$msg{'packet_count'},      '==', $pkt_total_size );
        sleep 3;
}

# Always end library in 1
1;
