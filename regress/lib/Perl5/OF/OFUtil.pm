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
  &enter_barrier
  &wait_for_barrier_exit
  &send_get_config_request
  &wait_for_get_config_reply
  &get_switch_features
  &get_config
  &set_config
  &run_black_box_test
  &create_flow_mod_from_udp
  &create_flow_mod_from_udp_actionbytes
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
  &get_default_black_box_pkt
  &get_default_black_box_pkt_len
  &for_all_port_pairs
  &for_all_ports
  &for_all_wildcards
  &for_all_port_triplets
  &forward_simple
  &flow_mod_length
  &combine_args 
  &get_original_value
  &generate_expect_packet
  &replace_sending_pkt 
  &create_vlan_pkt 
  &forward_simple_icmp
  &get_default_black_box_pkt_len_icmp
  &create_flow_mod_from_icmp_action
  &create_flow_mod_from_icmp
  &forward_simple_arp
  &get_default_black_box_pkt_len_arp
  &create_flow_mod_from_arp_action
  &create_flow_mod_from_arp
  &wait_for_two_flow_expired
  &get_dpinst
  &wait_for_echo_request
  &dpctl_del_flows
  &dpctl_show_flows
);

my $nf2_kernel_module_path        = 'datapath/linux-2.6';
my $nf2_kernel_module_name_no_ext = 'ofdatapath_netfpga';
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

sub start_ofprotocol {

	my ( $dpinst, $controller, $emerg ) = @_;
	if ( !$controller) { $controller = nftest_default_controllers(); }
	my $cmd;
	if (defined $emerg) {
		$cmd = "${openflow_dir}/secchan/ofprotocol $dpinst $controller --emerg-flow --inactivity-probe=10 &";
	} else {
		$cmd = "${openflow_dir}/secchan/ofprotocol $dpinst $controller --inactivity-probe=999999 &";
	}
	print "about to run $cmd\n";
	system($cmd);
}

sub setup_kmod {

	setup_pcap_interfaces();

	# verify kernel module not loaded
	my $of_kmod_loaded = `lsmod | grep ofdatapath`;
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
	`insmod ${openflow_dir}/datapath/linux-2.6/ofdatapath.ko`;

	`${openflow_dir}/utilities/dpctl adddp nl:0`;

	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`${openflow_dir}/utilities/dpctl addif nl:0 $iface`;
	}

        start_ofprotocol("nl:0", @_);
}

sub setup_NF2 {

	setup_pcap_interfaces();

    # load the openflow bitfile on the NetFPGA
	system("nf2_download ${openflow_dir}/hw-lib/nf2/openflow_switch.bit");
	sleep(2);

    # turn on phy(0-3) interrupt mask
    # in order to avoid asynchronous port_mod_change message
        `regwrite 0x04c006c 0xffff`;
        `regwrite 0x04c00ec 0xffff`;
        `regwrite 0x04c016c 0xffff`;
        `regwrite 0x04c01ec 0xffff`;

	# create openflow switch on four ports
	my $if_string = '';
	for (my $i = 5 ; $i <= 7 ; $i++) {
		$if_string .= nftest_get_iface("eth$i") . ',';
	}
	$if_string .= nftest_get_iface("eth8");

	print "about to create ofdatapath` punix:/var/run/test -i $if_string \& \n";
	system("${openflow_dir}/udatapath/ofdatapath punix:/var/run/test -i $if_string \&");

	sleep(1);

	start_ofprotocol("unix:/var/run/test", @_);
}


sub setup_user {
    setup_pcap_interfaces();

    # create openflow switch on four ports
    my $if_string = '';
    for (my $i = 5 ; $i <= 7 ; $i++) {
	$if_string .= nftest_get_iface("eth$i") . ',';
    }
    $if_string .= nftest_get_iface("eth8");

    print "about to create ofdatapath` punix:/var/run/test -i $if_string \& \n";
    system("${openflow_dir}/udatapath/ofdatapath punix:/var/run/test -i $if_string \&");

    start_ofprotocol("unix:/var/run/test", @_);

    #create a queue in each port
    for ($i = 1;$i <= 4; $i++) {
        system("${openflow_dir}/utilities/dpctl add-queue unix:/var/run/test $i 1 10");
    }


}

sub teardown_kmod {

	# check that we're root?
	my $who = `whoami`;
	if ( trim($who) ne 'root' ) { die "must be root\n"; }

	`killall ofprotocol`;

	# check if openflow kernel module loaded
	my $of_kmod_loaded = `lsmod | grep ofdatapath`;
	if ( $of_kmod_loaded eq "" ) { exit 0; }

	print "tearing down interfaces and datapaths\n";

	# remove interfaces from openflow
	for ( my $i = 5 ; $i <= 8 ; $i++ ) {
		my $iface = nftest_get_iface("eth$i");
		`${openflow_dir}/utilities/dpctl delif nl:0 $iface`;
	}

	`${openflow_dir}/utilities/dpctl deldp nl:0`;

	my $of_kmod_removed = `rmmod ofdatapath`;
	if ( $of_kmod_removed ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	$of_kmod_loaded = `lsmod | grep ofdatapath`;
	if ( $of_kmod_loaded ne "" ) {
		die "failed to remove kernel module... please fix!\n";
	}

	exit 0;
}

sub teardown_NF2 {
	teardown_user();
}

sub teardown_user {

	# check that we're root?
	my $who = `whoami`;
	if ( trim($who) ne 'root' ) { die "must be root\n"; }

	`killall ofdatapath`;
	`killall ofprotocol`;

	exit 0;
}

sub compare {
	my ( $test, $val, $op, $expected ) = @_;
	my $success = eval "$val $op $expected" ? 1 : 0;
	if ( !$success ) { die "$test: error $val not $op $expected\n"; }
}

sub create_controller_socket {
	my ($host, $port) = @_;
	print "about to make socket: tcp:$host:$port\n";
	my $sock = new IO::Socket::INET(
		LocalHost => $host,
		LocalPort => $port,
		Proto     => 'tcp',
		Listen    => 1,
		Reuse     => 1
	);
	die "Could not create socket: $!\n" unless $sock;
	# Don't hold to data - Jean II
	# This does NOT work, as it apply only to SOL_SOCKET
	$sock->sockopt(TCP_NODELAY, 1) or die "\$sock->sockopt NODELAY, 1: $! ($^E)";
	# This works properly - Jean II
	setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, pack("l", 1)) or die "\$sock->sockopt NODELAY, 1: $! ($^E)";
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

	# extract host and port from controller string if passed in
	if (defined $options{'controller'}) {
		# Assume fully qualified string :
		# tcp:<controller>:<port>
		# Jean II
	        ($controller, $failover) = split(/,/,$options{'controller'});
		($proto, $host, $port) = split(/:/,$controller);
		# Check for string missing the protocol - Jean II
		if ( ! defined ($port) ) {
		die "Invalid controller string $options{'controller'}"
		}
		#!!!
		print "Controller : using protocol $proto and port $port\n";
		}
                # Run controller from this process
		if ( ! defined ($port) ) {
			exec "$ENV{'OF_ROOT'}/controller/controller", "ptcp:";
		} else {
			exec "$ENV{'OF_ROOT'}/controller/controller", "p$proto:$port";
		}
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

sub enter_barrier {
    my ($ofp, $sock, $xid) = @_;

    my $hdr_args = {
	version => $of_ver,
	type => $enums{'OFPT_BARRIER_REQUEST'},
	length => $ofp->sizeof('ofp_header'),
	xid => $xid
    };
    my $request = $ofp->pack('ofp_header', $hdr_args);

    syswrite($sock, $request);

    print "Sent barrier request, xid:$xid\n";
}

sub wait_for_barrier_exit {
    my ($ofp, $sock, $xid) = @_;

    my $rcvd_msg;

    print "Receiving barrier reply, xid = $xid\n";

    sysread($sock, $rcvd_msg, 256)
	|| die "Failed to receive message: $!";

    my $num_read = length($rcvd_msg);
    my $msg_size = $ofp->sizeof('ofp_header');
    my $msg = $ofp->unpack('ofp_hello', $rcvd_msg);

    print Dumper($msg);
    compare("MsgVer", $$msg{'header'}{'version'}, '==', get_of_ver());
    compare("MsgType", $$msg{'header'}{'type'}, '==', $enums{'OFPT_BARRIER_REPLY'});
    compare("MsgLen", $$msg{'header'}{'length'}, '==', $msg_size);

    print "Received barrier reply, xid:$xid\n";

    return $msg;
}

sub send_get_config_request {
    my ($ofp, $sock, $xid) = @_;

    my $hdr_args = {
	version => $of_ver,
	type    => $enums{'OFPT_GET_CONFIG_REQUEST'},
	length  => $ofp->sizeof('ofp_header'),
	xid     => $xid
    };
    my $request = $ofp->pack('ofp_header', $hdr_args);

    syswrite($sock, $request);

    print "Sent get config request, xid:$xid\n";
}

sub wait_for_get_config_reply {
    my ($ofp, $sock, $xid) = @_;

    my $rcvd_msg;

    print "Receiving get config reply, xid = $xid\n";

    sysread($sock, $rcvd_msg, 256)
	|| die "Failed to receive message: $!";

    my $num_read = length($rcvd_msg);
    my $msg_size = $ofp->sizeof('ofp_switch_config');
    my $msg = $ofp->unpack('ofp_switch_config', $rcvd_msg);

    print Dumper($msg);
    compare("MsgVer", $$msg{'header'}{'version'}, '==', get_of_ver());
    compare("MsgType", $$msg{'header'}{'type'}, '==', $enums{'OFPT_GET_CONFIG_REPLY'});
    compare("MsgLen", $$msg{'header'}{'length'}, '==', $msg_size);

    print "Received get config reply, xid = $xid\n";

    return $msg;
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

	compare( "get_config msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_switch_config', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify header fields
	verify_header( $msg, 'OFPT_GET_CONFIG_REPLY', $msg_size );

	return $msg;
}

sub set_config {

	my ( $ofp, $sock, $options_ref, $flags, $miss_send_len ) = @_;
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

	# Send 'set_config_request' message
	syswrite( $sock, $set_config );

	# Give OF switch time to process the set_config
	usleep($$options_ref{'send_delay'});
}


sub run_black_box_test {

	my ( $test_ref, $argv_ref, $dont_exit ) = @_;

	my %options = nftest_init( $argv_ref, \@interfaces, );

        my ($proto, $host, $port) = nftest_parse_controllers( $options{'controller'} );
	print "using host $host and port $port\n";

	$sock = create_controller_socket($host, $port);

	my $total_errors = 0;
	try {

		# Wait for ofprotocol to connect
		print "waiting for ofprotocol to connect\n";
		my $new_sock = $sock->accept();

		do_hello_sequence( $ofp, $new_sock );

		# Launch PCAP listening interface
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
		if (!$dont_exit ) { exit($exitCode); }
	};
}

sub create_flow_mod_from_udp {
	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $flags,
		$wildcards, $chg_field, $chg_val, $vlan_id, $nw_tos, $cookie ) = @_;

	my $flow_mod_pkt;

	$flow_mod_pkt = create_flow_mod_from_udp_action( $ofp, $udp_pkt, $in_port,
		$out_port, $max_idle, $flags, $wildcards, 'OFPFC_ADD', $chg_field,
		$chg_val, $vlan_id, $nw_tos, $cookie );

	return $flow_mod_pkt;
}

sub flow_mod_length {
    my ($mod_type, $chg_field) = @_;

    my $action_length = 0;

    if ($mod_type eq 'drop') {
        $action_length = 0;
    } elsif (defined $chg_field) {
        if (($chg_field eq 'dl_src') || ($chg_field eq 'dl_dst')) {
            $action_length = $ofp->sizeof('ofp_action_dl_addr')
				+ $ofp->sizeof('ofp_action_output');
        } elsif (($chg_field eq 'nw_src') || ($chg_field eq 'nw_dst')) {
            $action_length = $ofp->sizeof('ofp_action_nw_addr')
				+ $ofp->sizeof('ofp_action_output');
        } elsif ($chg_field eq 'nw_tos') {
            $action_length = $ofp->sizeof('ofp_action_nw_tos')
				+ $ofp->sizeof('ofp_action_output');
        } elsif (($chg_field eq 'tp_src') || ($chg_field eq 'tp_dst')) {
            $action_length = $ofp->sizeof('ofp_action_tp_port')
				+ $ofp->sizeof('ofp_action_output');
        } elsif ($chg_field eq 'strip_vlan') {
            $action_length = $ofp->sizeof('ofp_action_header')
				+ $ofp->sizeof('ofp_action_output');
        } elsif ($chg_field eq 'vlan_vid') {
            $action_length = $ofp->sizeof('ofp_action_vlan_vid')
				+ $ofp->sizeof('ofp_action_output');
        } elsif ($chg_field eq 'vlan_pcp') {
            $action_length = $ofp->sizeof('ofp_action_vlan_pcp')
				+ $ofp->sizeof('ofp_action_output');
        } else {
            $action_length = $ofp->sizeof('ofp_action_output');
        }
    } elsif ($mod_type eq 'enqueue') {
        $action_length = $ofp->sizeof('ofp_action_enqueue');
	}
    else {
        $action_length = $ofp->sizeof('ofp_action_output');
    }

    my $length = $ofp->sizeof('ofp_flow_mod') + $action_length;
    return $length;
}

sub combine_args {
    my ($mod_type, $out_port, $chg_field, $chg_val, $queue_id) = @_;

    my @pad_6 = (0,0,0,0,0,0);
    my @pad_4 = (0,0,0,0);
    my @pad_3 = (0,0,0);
    my @pad_2 = (0,0);

    my $nw_addr_org;
    my $ok_org;

    my @dl_addr_org;
    my $chg_vlan_pcp_val;

    #OUTPUT
    #and No action for drops
    my $action_output_args;
    my $action_output;

    my $max_len;
    if ($out_port != $enums{'OFPP_CONTROLLER'}) {
        $max_len = 0;
    } else {
        $max_len = 65535;
    }
    if ($mod_type ne 'drop') {
        if ($mod_type eq 'enqueue') {
            $action_enqueue_args = {
			    type => $enums{'OFPAT_ENQUEUE'},
			    len => $ofp->sizeof('ofp_action_enqueue'),
			    port => $out_port,
			    pad  => \@pad_6,
                queue_id => $queue_id,
            };
            $action_enqueue = $ofp->pack('ofp_action_enqueue', $action_enqueue_args);
        }
        else {
            $action_output_args = {
			    type => $enums{'OFPAT_OUTPUT'},
			    len => $ofp->sizeof('ofp_action_output'),
			    port => $out_port,
			    max_len => $max_len,
            };
            $action_output = $ofp->pack('ofp_action_output', $action_output_args);
        }
    }

    #MODIFY ACTION
    my $action_mod_args;
    my $action_mod;
    if (defined $chg_field) {
	if ($chg_field eq 'dl_src') { #SET_DL_SRC
	    @dl_addr_org = NF2::PDU::get_MAC_address($chg_val);
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_DL_SRC'},
		len  => $ofp->sizeof('ofp_action_dl_addr'),
		dl_addr => \@dl_addr_org,
		pad  => \@pad_6,
	    };
	    $action_mod = $ofp->pack('ofp_action_dl_addr', $action_mod_args);
	} elsif ($chg_field eq 'dl_dst') { #SET_DL_DST
	    @dl_addr_org = NF2::PDU::get_MAC_address($chg_val);
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_DL_DST'},
		len  => $ofp->sizeof('ofp_action_dl_addr'),
		dl_addr => \@dl_addr_org,
		pad  => \@pad_6,
	    };
	    $action_mod = $ofp->pack('ofp_action_dl_addr', $action_mod_args);
	} elsif ($chg_field eq 'nw_src') { #SET_NW_SRC
	    ($nw_addr_org, $ok_org) = NF2::IP_hdr::getIP($chg_val);
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_NW_SRC'},
		len  => $ofp->sizeof('ofp_action_nw_addr'),
		nw_addr => $nw_addr_org,
	    };
	    $action_mod = $ofp->pack('ofp_action_nw_addr', $action_mod_args);
	} elsif ($chg_field eq 'nw_dst') { #SET_NW_DST
	    ($nw_addr_org, $ok_org) = NF2::IP_hdr::getIP($chg_val);
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_NW_DST'},
		len  => $ofp->sizeof('ofp_action_nw_addr'),
		nw_addr => $nw_addr_org,
	    };
	    $action_mod = $ofp->pack('ofp_action_nw_addr', $action_mod_args);
	} elsif ($chg_field eq 'nw_tos') { #SET_NW_TOS
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_NW_TOS'},
		len  => $ofp->sizeof('ofp_action_nw_tos'),
		nw_tos => $chg_val,
		pad => \@pad_3,
	    };
	    $action_mod = $ofp->pack('ofp_action_nw_tos', $action_mod_args);
	} elsif ($chg_field eq 'tp_src') { #SET_TP_SRC
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_TP_SRC'},
		len  => $ofp->sizeof('ofp_action_tp_port'),
		tp_port => $chg_val,
		pad  => \@pad_2,
	    };
	    $action_mod = $ofp->pack('ofp_action_tp_port', $action_mod_args);
	} elsif ($chg_field eq 'tp_dst') { #SET_TP_DST
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_TP_DST'},
		len  => $ofp->sizeof('ofp_action_tp_port'),
		tp_port => $chg_val,
		pad  => \@pad_2,
	    };
	    $action_mod = $ofp->pack('ofp_action_tp_port', $action_mod_args);
	} elsif ($chg_field eq 'strip_vlan') { #STRIP_VLAN
	    $action_mod_args = {
		type => $enums{'OFPAT_STRIP_VLAN'},
		len => $ofp->sizeof('ofp_action_header'),
		pad => \@pad_4,
	    };
	    $action_mod = $ofp->pack('ofp_action_header', $action_mod_args);
	} elsif ($chg_field eq 'vlan_vid') { #SET_VLAN_VID
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_VLAN_VID'},
		len => $ofp->sizeof('ofp_action_vlan_vid'),
		vlan_vid => $chg_val & 0x0fff,
		pad => \@pad_2,
	    };
	    $action_mod = $ofp->pack('ofp_action_vlan_vid', $action_mod_args);
	} elsif ($chg_field eq 'vlan_pcp') { #SET_VLAN_PCP
	    $chg_vlan_pcp_val = ($chg_val>>13) & 0x0007;
	    $action_mod_args = {
		type => $enums{'OFPAT_SET_VLAN_PCP'},
		len => $ofp->sizeof('ofp_action_vlan_pcp'),
		vlan_pcp => $chg_vlan_pcp_val,
		pad => \@pad_3,
	    };
	    $action_mod = $ofp->pack('ofp_action_vlan_pcp', $action_mod_args);
	} else {
	    $action_mod = undef;
	}
    } else {
	$action_mod = undef;
    }

    if (defined $action_mod) {
        $flow_mod_actions = $action_mod . $action_output;
    } elsif (defined $action_enqueue) {
        $flow_mod_actions = $action_enqueue;
    } else {
        $flow_mod_actions = $action_output;
    }

    return $flow_mod_actions;
}

sub create_flow_mod_from_udp_actionbytes {
        my ( $ofp, $udp_pkt, $in_port, $max_idle, $flags,
		$wildcards, $mod_type, $action_bytes, $vlan_id,
		$nw_tos, $cookie) = @_;

	$cookie = 0 if !defined($cookie);

        my $length = $ofp->sizeof('ofp_flow_mod') + length $action_bytes;

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

	my $dl_vlan;
	my $dl_vlan_pcp;
	if (defined $vlan_id) {
		$dl_vlan = $vlan_id & 0x0fff;
		$dl_vlan_pcp = (($vlan_id >> 13) & 0x0007);
	} else {
		$dl_vlan = 0xffff;
		$dl_vlan_pcp = 0x0;
	}

	my $match_nw_tos;
	if (defined $nw_tos) {
	    $match_nw_tos = $nw_tos & 0xfc;
	} else {
	    $match_nw_tos = 0;
	}

        my $match_args = {
                wildcards => $wildcards,
                in_port   => $in_port,
                dl_src    => \@src_mac_subarray,
                dl_dst    => \@dst_mac_subarray,
                dl_vlan   => $dl_vlan,
                dl_type   => 0x0800,
                dl_vlan_pcp => $dl_vlan_pcp,
                nw_src    => $src_ip,
                nw_dst    => $dst_ip,
                nw_tos    => $match_nw_tos,
                nw_proto  => 17,                                  #udp
                tp_src    => ${ $udp_pkt->{UDP_pdu} }->SrcPort,
                tp_dst    => ${ $udp_pkt->{UDP_pdu} }->DstPort
        };

        # organize flow_mod packet
        my $flow_mod_args = {
                header => $hdr_args,
                match  => $match_args,
                command   => $enums{"$mod_type"},
                idle_timeout  => $max_idle,
                hard_timeout  => $max_idle,
                flags  => $flags,
                priority => 0,
                buffer_id => -1,
                out_port => $enums{'OFPP_NONE'},
                cookie => $cookie,
        };
        my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );
        my $flow_mod_pkt = $flow_mod . $action_bytes;
        return $flow_mod_pkt;
}

sub create_flow_mod_from_udp_action {
        my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $flags,
		$wildcards, $mod_type, $chg_field, $chg_val, $vlan_id,
		$nw_tos, $cookie, $queue_id) = @_;

        if (   $mod_type ne 'drop'
               && $mod_type ne 'enqueue'
               && $mod_type ne 'OFPFC_ADD'
               && $mod_type ne 'OFPFC_DELETE'
               && $mod_type ne 'OFPFC_DELETE_STRICT')
        {
                die "Undefined flow mod type: $mod_type\n";
        }

        my $length_expect = flow_mod_length($mod_type, $chg_field);
        my $flow_mod_actions = combine_args($mod_type, $out_port, $chg_field, $chg_val, $queue_id);
        my $length = $ofp->sizeof('ofp_flow_mod') + length $flow_mod_actions;
        if( $length != $length_expect) {
                die "Mismatching length for $mod_type, $length != $length_expect\n";
        }

        $flow_mod_pkt =
          create_flow_mod_from_udp_actionbytes( $ofp, $udp_pkt, $in_port, $max_idle, $flags, $wildcards, $mod_type, $flow_mod_actions, $vlan_id, $nw_tos, $cookie);

        return $flow_mod_pkt;
}


sub wait_for_flow_expired {

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total, $idle_timeout,
		$cookie ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref, $pkt_len,
		$pkt_total, $idle_timeout, $cookie, undef);
}

sub wait_for_flow_expired_all {

	my ( $ofp, $sock, $options_ref, $cookie ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref,
		$$options_ref{'pkt_len'}, $$options_ref{'pkt_total'},
		$cookie, undef );
}

sub wait_for_flow_expired_readone {

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total, $idle_timeout,
		$cookie ) = @_;

	wait_for_flow_expired_readsize( $ofp, $sock, $options_ref, $pkt_len, $pkt_total, $idle_timeout,
		$cookie, $ofp->sizeof('ofp_flow_removed') );
}

sub wait_for_flow_expired_readsize {

	# can specify the reading size from socket (by the last argument, $read_size_)

	my ( $ofp, $sock, $options_ref, $pkt_len, $pkt_total, $idle_timeout,
		$cookie, $read_size_ ) = @_;
	wait_for_flow_expired_total_bytes( $ofp, $sock, $options_ref, ( $pkt_len * $pkt_total ),
		$pkt_total, $idle_timeout, $cookie, $read_size_ );
}

sub wait_for_flow_expired_total_bytes {
	my ( $ofp, $sock, $options_ref, $bytes, $pkt_total, $idle_timeout,
		$cookie, $read_size_ ) = @_;
	my $read_size;

	if ( defined $read_size_ ) {
		$read_size = $read_size_;
	} else {
		$read_size = 1512;
	}

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $read_size )
	  || die "Failed to receive ofp_flow_removed message: $!";

	#print HexDump ($recvd_mesg);

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_removed');
	compare( "ofp_flow_removed msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_removed', $recvd_mesg );

	#print Dumper($msg);

	# Verify fields
	compare( "ofp_flow_removed header version", $$msg{'header'}{'version'}, '==', $of_ver );
	compare( "ofp_flow_removed header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_REMOVED'} );
	compare( "ofp_flow_removed header length",  $$msg{'header'}{'length'},  '==', $msg_size );

	# Disable for platforms that don't have byte counts... - Jean II
	if ( not defined( $$options_ref{'ignore_byte_count'} ) ) {
	    compare( "ofp_flow_removed byte_count",     $$msg{'byte_count'},        '==', $bytes );
	}
	compare( "ofp_flow_removed packet_count",   $$msg{'packet_count'},      '==', $pkt_total );

	if ( defined $idle_timeout ) {
		compare( "ofp_flow_removed idle_timeout",   $$msg{'idle_timeout'},      '==', $idle_timeout );
	}

	if ( defined $cookie ) {
		compare( "ofp_flow_removed cookie",   $$msg{'cookie'}, '==', $cookie );
	}
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
	compare( "ofp_packet_in msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#	print Dumper($msg);

	# Verify fields
	compare( "ofp_packet_in header version", $$msg{'header'}{'version'}, '==', $of_ver );
	compare( "ofp_packet_in header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_PACKET_IN'} );
	compare( "ofp_packet_in header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "ofp_packet_in header length",  $$msg{'total_len'},         '==', $pkt_len );

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

sub get_default_black_box_pkt {
	my ($in_port, $out_port) = @_; 

	return get_default_black_box_pkt_len($in_port, $out_port, 64);
}

sub get_default_black_box_pkt_len {
	my ($in_port, $out_port, $len, $vlan_id) = @_;
 
	my $pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		VLAN_ID => $vlan_id,
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

	# Check if we need to be exhaustive or not...
	if ( defined( $$options_ref{'less_ports'} ) ) {
		# Just pick a pair of random ports
		my $source_port = int(rand($num_ports));
		my $offset = int(rand($num_ports - 1)) + 1;
		my $dest_port = ($source_port + $offset) % $num_ports;
		print "sending from port offset $source_port to $dest_port\n";
		&$fcn_ref( $ofp, $sock, $options_ref, $source_port, $dest_port, $wc);
	} else {
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
}

sub for_all_ports {

	my ( $ofp, $sock, $options_ref, $fcn_ref, $wc ) = @_;

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};


	# Check if we need to be exhaustive or not...
	if ( defined( $$options_ref{'less_ports'} ) ) {
		# Just pick one random port
		my $random_port = int(rand($num_ports));
		print "sending from port offset $random_port to (all port offsets but $random_port)\n";
		&$fcn_ref( $ofp, $sock, $options_ref, $random_port, -1, $wc);
	} else {
		# send from every port
		for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
			print "sending from port offset $i to (all port offsets but $i)\n";
			&$fcn_ref( $ofp, $sock, $options_ref, $i, -1, $wc);
		}
	}
}

sub for_all_wildcards {

	my ( $ofp, $sock, $options_ref, $fcn_ref) = @_;

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	my %wildcards = (
		0x000001 => 'IN_PORT',
		0x000002 => 'DL_VLAN',
		0x000004 => 'DL_SRC',
		0x000008 => 'DL_DST',
		#0x000010 => 'DL_TYPE',  # currently fixed at 0x0800
		#0x000020 => 'NW_PROTO', # currently fixed at 0x17
		0x000040 => 'TP_SRC',
		0x000080 => 'TP_DST',
		0x003f00 => 'NW_SRC',
		0x0fc000 => 'NW_DST',
		0x100000 => 'DL_VLAN_PCP',
		0x200000 => 'NW_TOS',
	);

	# Disable "1 ||" below for a more complete test
	# Check if we need to be exhaustive or not...
	if ( 1 || defined( $$options_ref{'less_ports'} ) ) {
		# Just pick a pair of random ports
		my $source_port = int(rand($num_ports));
		my $offset = int(rand($num_ports - 1)) + 1;
		my $dest_port = ($source_port + $offset) % $num_ports;

		print "sending from $source_port to $dest_port\n";

		for my $wc (sort keys %wildcards) {
			printf ("wildcards: 0x%04x ".$wildcards{$wc}."\n", $wc);
			&$fcn_ref( $ofp, $sock, $options_ref, $source_port, $dest_port, $wc);
		}
	} else {
		# send from every port
		for ( $i = 0 ; $i < $num_ports ; $i++ ) {
			my $j = ($i + 1) % 4;
			print "sending from $i to $j\n";
			for my $wc (sort keys %wildcards) {
				printf ("wildcards: 0x%04x ".$wildcards{$wc}."\n", $wc);
				&$fcn_ref( $ofp, $sock, $options_ref, $i, $j, $wc);
			}
		}
	}
}

sub for_all_port_triplets {
	my ( $ofp, $sock, $options_ref, $fcn_ref, $wc ) = @_;

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	# Check if we need to be exhaustive or not...
	if ( defined( $$options_ref{'less_ports'} ) ) {
		# Just pick a triplet of random ports
		my $source_port = int(rand($num_ports));
		my $offset = int(rand($num_ports - 1)) + 1;
		my $dest_port = ($source_port + $offset) % $num_ports;
		my $offset2 = int(rand($num_ports - 2)) + 1;
		if( $offset2 >= $offset) {
			$offset2++;
		}
		my $dest2_port = ($source_port + $offset2) % $num_ports;

		&$fcn_ref( $ofp, $sock, $options_ref, $source_port, $dest_port, $dest2_port, $wc);
	} else {
		# send from every port to every other port
		for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
			for ( my $j = 0 ; $j < $num_ports ; $j++ ) {
				my $o_port2 = ( ( $j + 1 ) % 4 );
				if ( $i != $j && $i != $o_port2) {
					&$fcn_ref( $ofp, $sock, $options_ref, $i, $j, $o_port2, $wc);
				}
			}
		}
	}
}

sub get_original_value {
    my ($chg_field, $test_pkt, $vlan_id) = @_;

	my $chg_val;
	if ($chg_field eq 'dl_src') {
		$chg_val = ${$test_pkt->{Ethernet_hdr}}->SA;
        } elsif ($chg_field eq 'dl_dst') {
                $chg_val = ${$test_pkt->{Ethernet_hdr}}->DA;
        } elsif ($chg_field eq 'nw_src') {
                $chg_val = ${$test_pkt->{IP_hdr}}->src_ip;
        } elsif ($chg_field eq 'nw_dst') {
                $chg_val = ${$test_pkt->{IP_hdr}}->dst_ip;
        } elsif ($chg_field eq 'tp_src') {
                $chg_val = ${$test_pkt->{UDP_pdu}}->SrcPort;
        } elsif ($chg_field eq 'tp_dst') {
                $chg_val = ${$test_pkt->{UDP_pdu}}->DstPort;
	} elsif ($chg_field eq 'vlan_vid') {
		if (defined $vlan_id) {
	                $chg_val = ${$test_pkt->{Ethernet_hdr}}->VLAN_ID;
		} else {
			$chg_val = 0x999; #12-bit value
		}
	} elsif ($chg_field eq 'vlan_pcp') {
		if (defined $vlan_id) {
	                $chg_val = ${$test_pkt->{Ethernet_hdr}}->VLAN_ID;
		} else {
			$chg_val = 0x6000; #Upper 3-bit is valid
		}
	} else {
		$chg_val = 0;
        }
	return $chg_val;
}

sub create_vlan_pkt {
	my ($in_port, $out_port, $pkt_len, $vlan_id, $chg_field) = @_;

	my $test_pkt_vlan;
	if ((defined $chg_field) && !(defined $vlan_id)) {
		if ($chg_field eq 'vlan_vid') {
			$test_pkt_vlan =  get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len, 0x999 );
		} elsif ($chg_field eq 'vlan_pcp') {
                        $test_pkt_vlan =  get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len, 0x6000 );
		}
	}
	return $test_pkt_vlan;
}

sub replace_sending_pkt {
	my ($chg_field, $chg_val, $test_pkt, $vlan_id) = @_; 

        my $dummy_chg_val;
	my $vlan_vid_val;
	my $vlan_pcp_val;
	if ($chg_field eq 'dl_src') {
		${$test_pkt->{Ethernet_hdr}}->SA("12:34:56:78:9a:bc");
        } elsif ($chg_field eq 'dl_dst') {
                ${$test_pkt->{Ethernet_hdr}}->DA("12:34:56:78:9a:bc");
        } elsif ($chg_field eq 'nw_src') {
                ${$test_pkt->{IP_hdr}}->src_ip("111.122.133.144");
		#Dummy rewrite in order to get re-calculated UDP checksum
                $dummy_chg_val = ${$test_pkt->{UDP_pdu}}->SrcPort;
                ${$test_pkt->{UDP_pdu}}->SrcPort($dummy_chg_val);
        } elsif ($chg_field eq 'nw_dst') {
                ${$test_pkt->{IP_hdr}}->dst_ip("111.122.133.144");
                #Dummy rewrite in order to get re-calculated UDP checksum
                $dummy_chg_val = ${$test_pkt->{UDP_pdu}}->SrcPort;
                ${$test_pkt->{UDP_pdu}}->SrcPort($dummy_chg_val);
        } elsif ($chg_field eq 'tp_src') {
                ${$test_pkt->{UDP_pdu}}->SrcPort(55);
        } elsif ($chg_field eq 'tp_dst') {
                ${$test_pkt->{UDP_pdu}}->DstPort(55);
	} elsif ($chg_field eq 'vlan_vid') {
		if (defined $vlan_id) {
			$vlan_pcp_val = $chg_val & 0xe000;
        	        ${$test_pkt->{Ethernet_hdr}}->VLAN_ID(0x0987 | $vlan_pcp_val);
		}
	} elsif ($chg_field eq 'vlan_pcp') {
		if (defined $vlan_id) {
	       	        $vlan_vid_val = $chg_val & 0x0fff;
	                ${$test_pkt->{Ethernet_hdr}}->VLAN_ID(0x6000 | $vlan_vid_val);
		}
        }
	return $test_pkt;
}

sub generate_expect_packet {
	my ( $chg_field, $chg_val, $ip_checksum_org, $udp_checksum_org, $test_pkt, $test_pkt_novlan, $test_pkt_vlan, $vlan_id ) = @_;

        # Need to expect modified header value when modify action has been issued.
        # Replace the value accordingly.
        if ($chg_field eq 'dl_src') {
                ${$test_pkt->{Ethernet_hdr}}->SA("$chg_val");
        }
        if ($chg_field eq 'dl_dst') {
                ${$test_pkt->{Ethernet_hdr}}->DA("$chg_val");
        }
        if ($chg_field eq 'nw_src') {
                ${$test_pkt->{IP_hdr}}->src_ip("$chg_val");
                ${$test_pkt->{IP_hdr}}->checksum($ip_checksum_org);
                ${$test_pkt->{UDP_pdu}}->Checksum($udp_checksum_org);
        }
        if ($chg_field eq 'nw_dst') {
                ${$test_pkt->{IP_hdr}}->dst_ip("$chg_val");
                ${$test_pkt->{IP_hdr}}->checksum($ip_checksum_org);
                ${$test_pkt->{UDP_pdu}}->Checksum($udp_checksum_org);
        }
        if ($chg_field eq 'tp_src') {
                ${$test_pkt->{UDP_pdu}}->SrcPort("$chg_val");
        }
        if ($chg_field eq 'tp_dst') {
                ${$test_pkt->{UDP_pdu}}->DstPort("$chg_val");
        }
	if ($chg_field eq 'strip_vlan') {
		$test_pkt_novlan->{UDP_pdu} = $test_pkt->{UDP_pdu};
		$test_pkt = $test_pkt_novlan;
	}
	if (($chg_field eq 'vlan_vid') || ($chg_field eq 'vlan_pcp')) {
		if (defined $vlan_id) {
	                ${$test_pkt->{Ethernet_hdr}}->VLAN_ID("$chg_val");
		} else {
			$test_pkt_vlan->{UDP_pdu} = $test_pkt->{UDP_pdu};
			$test_pkt = $test_pkt_vlan;
		}
	}	
	return $test_pkt;
}

sub forward_simple {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset,
		$wildcards, $type, $nowait, $chg_field, $vlan_id, $cookie ) = @_;

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

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'}, $vlan_id );
	my $test_pkt_novlan = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'}) ;
	my $test_pkt_vlan = create_vlan_pkt( $in_port, $out_port, $$options_ref{'pkt_len'}, $vlan_id, $chg_field);

	#print HexDump ($test_pkt->packed);
	#print HexDump ($test_pkt_novlan->packed);
	#print HexDump ($test_pkt_vlan->packed);

	my $ip_checksum_org = ${$test_pkt->{IP_hdr}}->checksum;
        my $udp_checksum_org = ${$test_pkt->{UDP_pdu}}->Checksum;

	my $chg_val;
	my $send_pkt;
	if (defined $chg_field) {
		#Save original value
		$chg_val = get_original_value($chg_field, $test_pkt, $vlan_id);
		#Replace the test packet
		$test_pkt = replace_sending_pkt($chg_field, $chg_val, $test_pkt, $vlan_id);
		#Get the replaced vlan id
		if (defined $vlan_id) {
			$vlan_id = ${$test_pkt->{Ethernet_hdr}}->VLAN_ID;
		}
	}

	my $flow_mod_pkt;
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};
	if ($type eq 'drop') {
		$flow_mod_pkt = create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port,
		                   $$options_ref{'max_idle'}, $flags,
				   $wildcards, 'drop', undef, undef,
				   $vlan_id, undef, $cookie, undef);
	} elsif ($type eq 'enqueue') {
		my $queue_id = 1;
		$flow_mod_pkt = create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port,
		                   $$options_ref{'max_idle'}, $flags,
				   $wildcards, 'enqueue', undef, undef,
				   $vlan_id, undef, $cookie, $queue_id);
	} else {
		$flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		                   $$options_ref{'max_idle'}, $flags,
				   $wildcards, $chg_field, $chg_val, $vlan_id,
				   undef, $cookie);
	}

	print HexDump($flow_mod_pkt);
	#print Dumper($flow_mod_pkt);

	# Send 'flow_mod' message
	syswrite( $sock, $flow_mod_pkt );
	print "sent flow_mod message\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	nftest_send( "eth" . ($in_port_offset + 1), $test_pkt->packed );

	my $expect_pkt;
	# Regenerate expected packet in case of performing modify_action
	if (defined $chg_field) {
		$expect_pkt  = generate_expect_packet($chg_field, $chg_val, $ip_checksum_org,
		      $udp_checksum_org, $test_pkt, $test_pkt_novlan, $test_pkt_vlan, $vlan_id);
	} else {
		$expect_pkt = $test_pkt;
	}

	if ($type eq 'any' || $type eq 'port' || $type eq 'enqueue') {
		# expect single packet
		print "expect single packet\n";
		nftest_expect( "eth" . ( $out_port_offset + 1 ), $expect_pkt->packed );
	}
	elsif ($type eq 'all') {
		# expect packets on all other interfaces
		print "expect multiple packets\n";
		for ( my $k = 0 ; $k < $$options_ref{'num_ports'} ; $k++ ) {
			if ( $k != $in_port_offset ) {
				nftest_expect( "eth" . ( $k + 1), $expect_pkt->packed );
			}
		}
	}
	elsif ($type eq 'controller') {
		# expect at controller
		
		my $recvd_mesg;
		sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
	
		# Inspect  message
		my $msg_size = length($recvd_mesg);
		my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $expect_pkt->packed );
		compare( "ofp_packet_in msg size", $msg_size, '==', $expected_size );
	
		my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );
	
		#print HexDump ($recvd_mesg);
		#print Dumper($msg);
	
		# Verify fields
		print "Verifying ofprotocol message for packet sent in to eth" . ( $in_port + 1 ) . "\n";
	
		verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );
	
		compare( "ofp_packet_in total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
		compare( "ofp_packet_in in_port",   $$msg{'in_port'},   '==', $in_port );
		compare( "ofp_packet_in reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );
	
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

	my $pkt_len = $$options_ref{'pkt_len'};
	if (defined $vlan_id) {
		$$options_ref{'pkt_len'} = $pkt_len + 4;
	}
	
	if (not defined($nowait)) {
		print "wait \n";
		wait_for_flow_expired_all( $ofp, $sock, $options_ref );	
	}

	$$options_ref{'pkt_len'} = $pkt_len;
}


#Sub functions for ICMP handling tests

sub get_default_black_box_pkt_len_icmp {
        my ($in_port, $out_port, $len) = @_;

        my $pkt_args = {
                DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
                SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
                src_ip => "192.168.200." .     ( $in_port ),
                dst_ip => "192.168.201." .     ( $out_port ),
                ttl    => 64,
                len    => $len,
                src_port => 1,
                dst_port => 0
        };
        return new_icmp_test_pkt NF2::ICMP_pkt(%$pkt_args);
}

#Sub functions for ICMP handling tests

sub get_default_black_box_pkt_len_arp {
        my ($in_port, $out_port, $len) = @_;

        my $pkt_args = {
                DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
                SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
                SenderIpAddr => "192.168.200." .     ( $in_port ),
                SenderEthAddr => "00:00:00:00:01:" . sprintf("%02d", $in_port),
                TargetIpAddr => "192.168.201." .     ( $out_port ),
                TargetEthAddr => "ff:ff:ff:ff:ff:ff",
                len    => $len,
        };
        return new_arp_test_pkt NF2::ARP_pkt(%$pkt_args);
}

sub create_flow_mod_from_icmp {

        my ( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards, $fool ) = @_;

        my $flow_mod_pkt;

        $flow_mod_pkt =
          create_flow_mod_from_icmp_action( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards,
                'OFPFC_ADD', $fool, $cookie );

        return $flow_mod_pkt;
}

sub create_flow_mod_from_icmp_action {

        my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $flags,
		$wildcards, $mod_type, $fool, $cookie ) = @_;

	$cookie = 0 if !defined($cookie);

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
                dl_vlan_pcp => 0x00,
                nw_src    => $src_ip,
                nw_dst    => $dst_ip,
                nw_tos    => 0,
                nw_proto  => 1,                                  #ICMP
                tp_src    => $icmp_type,
                tp_dst    => $icmp_code
        };

        my $max_len;
        if ($out_port != $enums{'OFPP_CONTROLLER'}) {
            $max_len = 0;
        } else {
            $max_len = 65535;
        }
        my $action_output_args = {
                type => $enums{'OFPAT_OUTPUT'},
                len => $ofp->sizeof('ofp_action_output'),
                port => $out_port,
                max_len => $max_len,
        };

        my $action_output = $ofp->pack( 'ofp_action_output', $action_output_args );

        my $flow_mod_args = {
                header => $hdr_args,
                match  => $match_args,

                #               command   => $enums{$mod_type},
                command   => $enums{"$mod_type"},
                idle_timeout  => $max_idle,
                hard_timeout  => $max_idle,
                flags  => $flags,
                priority => 0,
                buffer_id => -1,
                out_port => $enums{'OFPP_NONE'},
                cookie => $cookie,
        };
        my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

        my $flow_mod_pkt = $flow_mod . $action_output;

        return $flow_mod_pkt;
}

sub create_flow_mod_from_arp {

        my ( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards, $fool ) = @_;

        my $flow_mod_pkt;

        $flow_mod_pkt =
          create_flow_mod_from_arp_action( $ofp, $icmp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards,
                'OFPFC_ADD', $fool );

        return $flow_mod_pkt;
}

sub create_flow_mod_from_arp_action {

        my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards, $mod_type, $fool ) = @_;

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
        my $ref_to_arp_hdr  = ( $udp_pkt->{'ARP_hdr'} );

        # pointer to array
        my $eth_hdr_bytes    = $$ref_to_eth_hdr->{'bytes'};
        my $arp_hdr_bytes    = $$ref_to_arp_hdr->{'bytes'};
        my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
        my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

        my @src_ip_subarray = @{$arp_hdr_bytes}[ 14 .. 17 ];
        my @dst_ip_subarray = @{$arp_hdr_bytes}[ 24 .. 27 ];

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

        my $arp_opcode;
        if ($fool == 1) {
                $arp_opcode = ~(${$ref_to_arp_hdr}->Op);
        } else {
                $arp_opcode = (${$ref_to_arp_hdr}->Op);
        }

        my $match_args = {
                wildcards => $wildcards,
                in_port   => $in_port,
                dl_src    => \@src_mac_subarray,
                dl_dst    => \@dst_mac_subarray,
                dl_vlan   => 0xffff,
                dl_type   => 0x0806,
                dl_vlan_pcp => 0x00,
                nw_src    => $src_ip,
                nw_dst    => $dst_ip,
                nw_proto  => $arp_opcode,
                tp_src    => 0x0000,
                tp_dst    => 0x0000
        };

        my $max_len;
        if ($out_port != $enums{'OFPP_CONTROLLER'}) {
            $max_len = 0;
        } else {
            $max_len = 65535;
        }
        my $action_output_args = {
                type => $enums{'OFPAT_OUTPUT'},
                len => $ofp->sizeof('ofp_action_output'),
                port => $out_port,
                max_len => $max_len,
        };

        my $action_output = $ofp->pack( 'ofp_action_output', $action_output_args );

        my $flow_mod_args = {
                header => $hdr_args,
                match  => $match_args,

                #               command   => $enums{$mod_type},
                command   => $enums{"$mod_type"},
                idle_timeout  => $max_idle,
                hard_timeout  => $max_idle,
                flags  => $flags,
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

	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

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
                  create_flow_mod_from_icmp( $ofp, $test_pkt, $in_port, $fool_port, $$options_ref{'max_idle'}, $flags, $wildcards, $fool );
                print HexDump($flow_mod_pkt_fool);
                #print Dumper($flow_mod_pkt_fool);
                # Send 'flow_mod' message
                print $sock $flow_mod_pkt_fool;
                print "sent flow_mod message\n";
                # Give OF switch time to process the flow mod
                usleep($$options_ref{'send_delay'});
        }

        my $flow_mod_pkt =
          create_flow_mod_from_icmp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $flags, $wildcards, 0 );

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
                compare( "ofp_packet_in icmp msg size", $msg_size, '==', $expected_size );

                my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

                #print HexDump ($recvd_mesg);
                #print Dumper($msg);

                # Verify fields
                print "Verifying ofprotocol message for packet sent in to eth" . ( $in_port + 1 ) . "\n";

                verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

                compare( "ofp_packet_in icmp total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
                compare( "ofp_packet_in icmp in_port",   $$msg{'in_port'},   '==', $in_port );
                compare( "ofp_packet_in icmp reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );

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

        my $pkt_len = $$options_ref{'pkt_len'};
        if (defined $vlan_id) {
                $$options_ref{'pkt_len'} = $pkt_len + 4;
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

sub forward_simple_arp {

        my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $wildcards, $type, $fool, $nowait ) = @_;

        my $in_port = $in_port_offset + $$options_ref{'port_base'};
        my $out_port;

        my $fool_port = 0;
        my $flow_mod_pkt_fool;

	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

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

        my $test_pkt = get_default_black_box_pkt_len_arp( $in_port, $out_port, $$options_ref{'pkt_len'} );

        #print HexDump ( $test_pkt->packed );

        if (($fool == 1) && ($type eq 'port') && ($wildcards != 0x40)) {
                my $flow_mod_pkt_fool =
                  create_flow_mod_from_arp( $ofp, $test_pkt, $in_port, $fool_port, $$options_ref{'max_idle'}, $flags, $wildcards, $fool );
                print HexDump($flow_mod_pkt_fool);
                #print Dumper($flow_mod_pkt_fool);
                # Send 'flow_mod' message
                print $sock $flow_mod_pkt_fool;
                print "sent flow_mod message\n";
                # Give OF switch time to process the flow mod
                usleep($$options_ref{'send_delay'});
        }

        my $flow_mod_pkt =
          create_flow_mod_from_arp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $flags, $wildcards, 0 );

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
                compare( "ofp_packet_in arp msg size", $msg_size, '==', $expected_size );

                my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

                #print HexDump ($recvd_mesg);
                #print Dumper($msg);

                # Verify fields
                print "Verifying ofprotocol message for packet sent in to eth" . ( $in_port + 1 ) . "\n";

                verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

                compare( "ofp_packet_in arp total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
                compare( "ofp_packet_in arp in_port",   $$msg{'in_port'},   '==', $in_port );
                compare( "ofp_packet_in arp reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );

                # verify packet was unchanged!
                my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
                if ( $recvd_pkt_data ne $test_pkt->packed ) {
                        die "ERROR: sending from eth"
                          . ($in_port_offset + 1)
                          . " received packet data didn't match packet sent\n";
                }
        }
        else {
                die "invalid input to forward_simple_arp\n";
        }

        my $pkt_len = $$options_ref{'pkt_len'};
        if (defined $vlan_id) {
                $$options_ref{'pkt_len'} = $pkt_len + 4;
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
        my $expected_size = $ofp->sizeof('ofp_flow_removed');
        #compare( "msg size", length($recvd_mesg), '==', $expected_size );

        my $msg = $ofp->unpack( 'ofp_flow_removed', $recvd_mesg );

        #print Dumper($msg);

        # Verify fields
        #compare( "header version", $$msg{'header'}{'version'}, '==', $of_ver );
        #compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_REMOVED'} );
        #compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
        #compare( "byte_count",     $$msg{'byte_count'},        '==', $bytes );
        #compare( "packet_count",   $$msg{'packet_count'},      '==', $pkt_total_size );
        sleep 3;
}

sub wait_for_echo_request {

        my ( $ofp, $sock, $options_ref, $read_size_ ) = @_;
        my $read_size;

        if ( defined $read_size_ ) {
                $read_size = $read_size_;
        } else {
                $read_size = 1512;
        }

        my $recvd_mesg;
        sysread( $sock, $recvd_mesg, $read_size )
          || die "Failed to receive ofp_echo_request message: $!";

        #print HexDump ($recvd_mesg);

        # Inspect  message
        my $msg_size      = length($recvd_mesg);
        my $expected_size = $ofp->sizeof('ofp_header');
        compare( "ofp_echo_reply msg size", length($recvd_mesg), '==', $expected_size );

        my $msg = $ofp->unpack( 'ofp_header', $recvd_mesg );

        #print Dumper($msg);
        # Verify fields
        compare( "header version", $$msg{'version'}, '==', $of_ver );
        compare( "header type",    $$msg{'type'},    '==', $enums{'OFPT_ECHO_REQUEST'} );
        compare( "header length",  $$msg{'length'},  '==', $msg_size );

        return $$msg{'xid'};
}

sub get_dpinst {
        my ($options_ref) = @_;

        my $platform = $$options_ref{'common-st-args'};
        my $kmod_dpinst = "nl:0";
        my $user_dpinst = "unix:/var/run/test";
        my $dpinst;

	if ( not defined( $$options_ref{'listener'} ) ) {
	        if (($platform eq 'user') or ($platform eq 'user_veth')) {
	                $dpinst = $user_dpinst;
	        } else {
	                $dpinst = $kmod_dpinst;
	        }
	} else {
		# For some platform, we have absolutely no way to guess
		# the proper argument to dpctl.
		# For example, on the HP test, it means guessing the IP
		# address and the port. So, we need a bit of help...
		# Jean II
		$dpinst = $$options_ref{'listener'};
	}

        return $dpinst;
}

sub dpctl_del_flows {
        my ($options_ref) = @_;

        my $dpinst = get_dpinst($options_ref);
        `$ENV{'OF_ROOT'}/utilities/dpctl del-flows $dpinst`;
}

sub dpctl_show_flows {
        my ($options_ref) = @_;

        my $dpinst = get_dpinst($options_ref);
        system("$ENV{'OF_ROOT'}/utilities/dpctl dump-flows $dpinst");
}

# Always end library in 1
1;
