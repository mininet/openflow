####################################
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

package OF::OFPacketLib;

use strict;

use Convert::Binary::C;
use Data::Dumper;
use Data::HexDump;
use OF::Base;

use Exporter;
use vars qw(@ISA @EXPORT);  # needed cos strict is on
@ISA = qw(Exporter);
@EXPORT = qw($ofp %enums);

our $ofp = Convert::Binary::C->new;

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


#!!!
$ofp->configure(%config);

#$ofp->configure('Include' => ['/usr/include']);

# set to big endian for network order, regardless of machine endianness
$ofp->configure(ByteOrder => 'BigEndian');

# ensure environment variables set before reading C file
check_OF_vars_set();

# load C structs and enums
my $of_file = $ENV{'OF_ROOT'}.'/include/openflow/openflow.h';
#print "$of_file\n";

eval { $ofp->parse_file($of_file) };
if ($@) { die "error in parse_file $@\n"; }

#!!!
#print $ofp->sizeof('ofp_action') . "\n";
#print $ofp->sizeof('ofp_packet_in') . "\n";
#print $ofp->sizeof('ofp_flow_mod') . "\n";
#print $ofp->offsetof('ofp_action', 'arg.output') . "\n";
#exit 1;

my @enum_list = $ofp->enum;
our %enums; # "global" enum hash
#print Dumper(@enum_list);
foreach my $enum_hash_ref (@enum_list) {
	my %enum_hash = %{$enum_hash_ref->{'enumerators'}};
	while( my($key, $val) = each(%enum_hash) ) {
		$enums{$key} = $val;
	}
}

1;

__END__
