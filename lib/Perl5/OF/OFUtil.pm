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

use NF2::TestLib;
use Exporter;
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
);

my $nf2_kernel_module_path = 'datapath_nf2/linux-2.6'; 
my $nf2_kernel_module_name = 'openflow_hw_nf2.ko';

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

# Always end library in 1
1;
