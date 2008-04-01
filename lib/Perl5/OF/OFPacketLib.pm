#####################################
# vim:set shiftwidth=2 softtabstop=2 expandtab:
#
# $Id: PacketLib.pm 3074 2007-12-06 03:01:04Z grg $
#
# This provides functions for manipulating packets.
#
# The goal is to provide functions that make it easy to create and
# manipulate packets, so that we can avoid stupid errors.
#
#####################################

use Convert::Binary::C;
use Data::Dumper;
use Data::HexDump;
use OF::Base;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw(&ofp &ofp_pack $ofp &packed);

my $ofp = Convert::Binary::C->new;

# Convert::Binary::C config generated with `ccconfig`
# should run this during make to customize to a machine
my %config = (
            'Alignment' => 4,
            'Assert' => [
                          'cpu(i386)',
                          'machine(i386)',
                          'system(linux)',
                          'system(posix)',
                          'system(unix)'
                        ],
            'ByteOrder' => 'LittleEndian',
            'CharSize' => 1,
            'CompoundAlignment' => 1,
            'Define' => [
                          '__CHAR_BIT__=8',
                          '__DBL_DIG__=15',
                          '__DBL_EPSILON__=2.2204460492503131e-16',
                          '__DBL_MANT_DIG__=53',
                          '__DBL_MAX_10_EXP__=308',
                          '__DBL_MAX_EXP__=1024',
                          '__DBL_MAX__=1.7976931348623157e+308',
                          '__DBL_MIN_10_EXP__=(-307)',
                          '__DBL_MIN_EXP__=(-1021)',
                          '__DBL_MIN__=2.2250738585072014e-308',
                          '__DECIMAL_DIG__=21',
                          '__ELF__=1',
                          '__FLT_DIG__=6',
                          '__FLT_EPSILON__=1.19209290e-7F',
                          '__FLT_EVAL_METHOD__=2',
                          '__FLT_MANT_DIG__=24',
                          '__FLT_MAX_10_EXP__=38',
                          '__FLT_MAX_EXP__=128',
                          '__FLT_MAX__=3.40282347e+38F',
                          '__FLT_MIN_10_EXP__=(-37)',
                          '__FLT_MIN_EXP__=(-125)',
                          '__FLT_MIN__=1.17549435e-38F',
                          '__FLT_RADIX__=2',
                          '__GNUC_MINOR__=1',
                          '__GNUC_PATCHLEVEL__=2',
                          '__GNUC_RH_RELEASE__=14',
                          '__GNUC__=4',
                          '__INT_MAX__=2147483647',
                          '__LDBL_DIG__=18',
                          '__LDBL_EPSILON__=1.08420217248550443401e-19L',
                          '__LDBL_MANT_DIG__=64',
                          '__LDBL_MAX_10_EXP__=4932',
                          '__LDBL_MAX_EXP__=16384',
                          '__LDBL_MAX__=1.18973149535723176502e+4932L',
                          '__LDBL_MIN_10_EXP__=(-4931)',
                          '__LDBL_MIN_EXP__=(-16381)',
                          '__LDBL_MIN__=3.36210314311209350626e-4932L',
                          '__LONG_LONG_MAX__=9223372036854775807LL',
                          '__LONG_MAX__=2147483647L',
                          '__NO_INLINE__=1',
                          '__PTRDIFF_TYPE__=int',
                          '__SCHAR_MAX__=127',
                          '__SHRT_MAX__=32767',
                          '__SIZE_TYPE__=unsigned int',
                          '__USER_LABEL_PREFIX__=',
                          '__WCHAR_TYPE__=long int',
                          '__WINT_TYPE__=unsigned int',
                          '__attribute__(x)=',
                          '__builtin_va_list=int',
                          '__gnu_linux__=1',
                          '__i386=1',
                          '__i386__=1',
                          '__linux=1',
                          '__linux__=1',
                          '__unix=1',
                          '__unix__=1',
                          'i386=1',
                          'linux=1',
                          'unix=1'
                        ],
            'DisabledKeywords' => [
                                    'restrict'
                                  ],
            'DoubleSize' => 8,
            'EnumSize' => 4,
            'FloatSize' => 4,
            'HasCPPComments' => 1,
            'Include' => [
                           '/usr/lib/gcc/i386-redhat-linux/4.1.2/include',
                           '/usr/include'
                         ],
            'IntSize' => 4,
            'KeywordMap' => {
                              '__asm' => 'asm',
                              '__asm__' => 'asm',
                              '__complex' => undef,
                              '__complex__' => undef,
                              '__const' => 'const',
                              '__const__' => 'const',
                              '__extension__' => undef,
                              '__imag' => undef,
                              '__imag__' => undef,
                              '__inline' => 'inline',
                              '__inline__' => 'inline',
                              '__real' => undef,
                              '__real__' => undef,
                              '__restrict' => 'restrict',
                              '__restrict__' => 'restrict',
                              '__signed' => 'signed',
                              '__signed__' => 'signed',
                              '__volatile' => 'volatile',
                              '__volatile__' => 'volatile'
                            },
            'LongDoubleSize' => 12,
            'LongLongSize' => 8,
            'LongSize' => 4,
            'PointerSize' => 4,
            'ShortSize' => 2,
            'UnsignedChars' => 0
          );


$ofp->configure(%config);

# set to big endian for network order, regardless of machine endianness
$ofp->configure(ByteOrder => 'BigEndian');
$ofp->configure(Alignment => 1);

# ensure environment variables set before reading C file
check_OF_vars_set();

# load C structs and enums
my $of_file = $ENV{'OF_ROOT'}.'/include/openflow.h';
print "$of_file\n";

eval { $ofp->parse_file($of_file) };
if ($@) { die "error in parse_file $@\n"; }

#print "finished parsing\n";
#sub ofp_pack 
#  {
#    my ($template, $list) = @_;
#    return $ofp->pack($template, $list);
#  }

# there has to be some way to just export the ofp var... but I can't find it!
sub ofp
  {
    return $ofp;
  }

################################################################################
# UDP packet
################################################################################

package OF::UDP_pkt;

use Carp;
use strict;
use vars qw(@ISA);
@ISA = qw(NF2::IP_pkt);

use constant PROTO_UDP => 17;
use constant DEFAULT_DATA_LEN => 20;
use constant UDP_HDR_LEN => 8;

sub new   # Ethernet_hdr
  {
    my ($class, %arg) = @_;

    my $force = defined($arg{'force'}) && $arg{'force'};

    # Set various arguments
    $arg{'proto'} = PROTO_UDP if (!$force || !defined($arg{'proto'}));

    # Create either payload or the udp_len if the other is defined
    if (!defined($arg{'udp_len'}) && !defined($arg{'data'}) && defined($arg{'len'})) {
      $arg{'udp_len'} = $arg{'len'} - NF2::IP_pkt::MIN_LEN();
    }

    if (defined($arg{'udp_len'}) && $arg{'udp_len'} < UDP_HDR_LEN) {
      $arg{'udp_len'} = UDP_HDR_LEN;
    }
    if (defined($arg{'udp_len'}) && !defined($arg{'data'}) &&
        $arg{'udp_len'} > UDP_HDR_LEN) {
      $arg{'data'} = [ map {int(rand(256))} (1..($arg{'udp_len'} - UDP_HDR_LEN)) ];
    }
    
    # Create the UDP PDU
    my $UDP_pdu = new NF2::UDP(%arg);

    # Update the UDP length if necessary
    if (!defined($arg{'udp_len'})) {
      $UDP_pdu->Length($UDP_pdu->length_in_bytes());
    }

    # Calculate the length of the packet
    $arg{'len'} = NF2::IP_pkt::MIN_LEN() + $UDP_pdu->length_in_bytes() if 
        (!$force || !defined($arg{'len'}));

    $arg{'frag'} = 0x4000 if (!$force && !defined($arg{'frag'}));
    $arg{'ttl'} = 64 if (!$force || !defined($arg{'ttl'}));

    # Create the packet
    my $Pkt = $class->NF2::IP_pkt::new(%arg);

    # Create the parts list that says what PDUs are inside the packet
    my @parts = ('Ethernet_hdr', 'IP_hdr', 'UDP_pdu');

    # Replace the parts array and stuff the new PDU
    $Pkt->{'UDP_pdu'} = \$UDP_pdu;
    $Pkt->{'Parts'} = \@parts;
    delete($Pkt->{'payload'});

    # Update the IP_hdr in the UDP PDU
    $UDP_pdu->IP_hdr($Pkt->{'IP_hdr'});
    $UDP_pdu->Checksum($arg{'udp_checksum'}) if (defined($arg{'udp_checksum'}));

    return $Pkt;
  }

# Change both headers
sub set {
  my ($self, %arg) = @_;

  # Update the various UDP fields if appropriate
  ${$self->{UDP_pdu}}->SrcPort($arg{'src_port'}) if (defined $arg{'src_port'});
  ${$self->{UDP_pdu}}->DstPort($arg{'dst_port'}) if (defined $arg{'dst_port'});
  ${$self->{UDP_pdu}}->Length($arg{'udp_len'}) if (defined $arg{'udp_len'});     
  ${$self->{UDP_pdu}}->Data($arg{'data'}) if (defined $arg{'data'});  
  # Update the UDP length if necessary
  if (!defined($arg{'udp_len'}) && defined($arg{'data'})) {
    ${$self->{UDP_pdu}}->Length(${$self->{UDP_pdu}}->length_in_bytes());
  }
  ${$self->{UDP_pdu}}->IP_hdr($arg{'ip_hdr'}) if (defined $arg{'ip_hdr'});  
  ${$self->{UDP_pdu}}->Checksum($arg{'udp_checksum'}) if (defined($arg{'udp_checksum'}));

  # Change the DA or SA (but not the Ethertype since this is IP)
  ${$self->{Ethernet_hdr}}->DA($arg{'DA'}) if (defined $arg{'DA'});
  ${$self->{Ethernet_hdr}}->SA($arg{'SA'}) if (defined $arg{'SA'});

  # Update the length if the data has changed
  if (defined $arg{'data'}) {
    # Calculate the length of the packet
    $arg{'len'} = NF2::IP_pkt::MIN_LEN() + ${$self->{UDP_pdu}}->length_in_bytes();
    $arg{'dgram_len'} = $arg{'len'} - NF2::IP_pkt::ETH_HDR_LEN;
  }

  # Change allowable IP header options
  ${$self->{IP_hdr}}->tos($arg{'tos'}) if (defined $arg{'tos'});
  ${$self->{IP_hdr}}->dgram_len($arg{'dgram_len'}) if (defined $arg{'dgram_len'});
  ${$self->{IP_hdr}}->dgram_id($arg{'dgram_id'}) if (defined $arg{'dgram_id'});
  ${$self->{IP_hdr}}->frag($arg{'frag'}) if (defined $arg{'frag'});
  ${$self->{IP_hdr}}->ttl($arg{'ttl'}) if (defined $arg{'ttl'});
  ${$self->{IP_hdr}}->src_ip($arg{'src_ip'}) if (defined $arg{'src_ip'});
  ${$self->{IP_hdr}}->dst_ip($arg{'dst_ip'}) if (defined $arg{'dst_ip'});
  ${$self->{IP_hdr}}->checksum($arg{'checksum'}) if (defined $arg{'checksum'});
}

# Get values from the various headers
sub get {
  my ($self, $field) = @_;

  # UDP header fields
  return ${$self->{UDP_pdu}}->SrcPort if ($field eq'src_port');
  return ${$self->{UDP_pdu}}->DstPort if ($field eq'dst_port');
  return ${$self->{UDP_pdu}}->Length if ($field eq'udp_len');     
  return ${$self->{UDP_pdu}}->Data if ($field eq'data');
  return ${$self->{UDP_pdu}}->IP_hdr if ($field eq'ip_hdr');  
  return ${$self->{UDP_pdu}}->Checksum if ($field eq 'udp_checksum');

  # If we get to here then we must be dealing with an IP packet field (hopefully)
  return $self->NF2::IP_pkt::get($field);
}

# Decrement the TTL
sub decrement_ttl {
  my ($self, %arg) = @_;

  ${$self->{IP_hdr}}->ttl(${$self->{IP_hdr}}->ttl - 1);
}

################################################################################
# OFP Header
################################################################################
package OF::OFP_hdr;

use vars qw(@ISA);
@ISA = qw(NF2::PDU);

use constant OFPT_MAX => 14;

sub new   # OFP
  {
    print "in OFP::new\n";
    my ($class,%arg) = @_;

    my $ofp = $class->NF2::PDU::new();

    @{$ofp->{'bytes'}}[0..7] = (
	0x01,			# Version - always 1
	0x00,   		# Type  
        0x00, 0x00,    		# Length
	0x00, 0x00, 0x00, 0x00	# Transaction ID (XID)
    );

    bless $ofp, $class;

    $ofp->Version($arg{'version'}) if (defined $arg{'version'});
    $ofp->Type($arg{'type'}) if (defined $arg{'type'});
    $ofp->Length($arg{'length'}) if (defined $arg{'length'});     
    $ofp->XID($arg{'xid'}) if (defined($arg{'xid'}));
    $ofp->Data($arg{'data'}) if (defined($arg{'data'}));

    $ofp;
  }

sub Version
  {
    my ($self, $val) = @_;

    if (defined $val) {
     my $err = sprintf "Source port is %d (0x%02x) but it must be >= 0 and <= 0xff", $val, $val;
      if (($val < 0x0) or ($val > 0xff)) { die "$err" }
      @{$self->{'bytes'}}[0] = int ($val);

    }
    return (@{$self->{'bytes'}}[0]);
  }

sub Type
  {
    my ($self, $val) = @_;

    if (defined $val) {
      my $err = sprintf "Type is %d (0x%02x) but it must be >= 0 and <= 0xffff", $val, $val;
      if (($val < 0x0) or ($val > OFPT_MAX)) { die "$err" }
      @{$self->{'bytes'}}[1] = int ($val);
    }
    return (@{$self->{'bytes'}}[1]);
  }

sub Length 
  {
    my ($self, $val) = @_;

    if (defined $val) {
      my $err = sprintf "Length is %d (0x%02x) but it must be >= 0 and <= 0xffff", $val, $val;
      if (($val < 0x0) or ($val > 0xffff)) { die "$err" }
      @{$self->{'bytes'}}[2] = int ($val/256);
      @{$self->{'bytes'}}[3] = int ($val%256);

    }
    return (256*@{$self->{'bytes'}}[2] + @{$self->{'bytes'}}[3]);
  }

sub XID 
  {
    my ($self, $val) = @_;

    if (defined $val) {      my $err = sprintf "Length is %d (0x%02x) but it must be >= 0 and <= 0xffffffff", $val, $val;
      if (($val < 0x0) or ($val > 0xffffffff)) { die "$err" }
      @{$self->{'bytes'}}[4] = int (($val & 0xff000000) >> 24);
      @{$self->{'bytes'}}[5] = int (($val & 0x00ff0000) >> 16);
      @{$self->{'bytes'}}[6] = int (($val & 0x0000ff00) >> 8);
      @{$self->{'bytes'}}[7] = int ($val & 0x000000ff);
    }
    return (
	256*256*256*@{$self->{'bytes'}}[4] +
	256*256*@{$self->{'bytes'}}[5] + 
	256*@{$self->{'bytes'}}[6] + 
	@{$self->{'bytes'}}[7]);
    #return pack 'C4', $self->bytes[4], $self->bytes[5], $self->bytes[6], $self->bytes[7];
    # probably some cleaner way to use pack 'N' to return a value
  }


sub Data 
  {
    my ($self) = shift;
    my $len = scalar(@_);

    if ($len > 0) {
      my @data;
      if ($len == 1) {
        # Work out if we're dealing with a reference or not
        if (ref($_[0])) {
          @data = @{$_[0]};
        }
        else {
          @data = unpack('C*', shift);
        }
      }
      else {
        @data = @_;
      }

      if (0+@data) {
        @{$self->{'bytes'}} = (@{$self->{'bytes'}}[0..7] , @data);
      }
      else {
        @{$self->{'bytes'}} = @{$self->{'bytes'}}[0..7];
      }

    }
    else {
      $len = scalar(@{$self->{'bytes'}});
    }

    if ($len >= 8 ) {
      return (@{$self->{'bytes'}}[8..(scalar(@{$self->{'bytes'}}) - 1)]);
    }
    else {
      return ();
    }
  }

1;

__END__



-
