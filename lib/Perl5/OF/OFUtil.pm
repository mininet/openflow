#############################################################
# $Id: OFUtil.pm 3161 2007-12-13 21:08:05Z grg $
#
# Module provides basic functions for use by OF Perl scripts.
#
# Revisions:
#
##############################################################

package OF::OFUtil;
use NF2::TestLib;
use Exporter;
@ISA = ('Exporter');
@EXPORT = qw( &trim &send_and_count &expect_and_count 
	&save_counters &verify_counters
            );

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

# Always end library in 1
1;
