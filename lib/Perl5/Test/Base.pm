#############################################################
# $Id: Base.pm 3909 2008-06-06 03:31:57Z brandonh $
#
# Module provides basic functions for use by NF2 Perl scripts.
#
# Revisions:
#
##############################################################

package Test::Base;
use Exporter;
@ISA = ('Exporter');
@EXPORT = qw( &check_NF2_vars_set
            );

##############################################################
#
# Define a my_die function if it doesn't already exist
#
##############################################################

if (!defined(&my_die)) {
	eval('
	  sub my_die {
	  my $mess = shift @_;
	  (my $cmd = $0) =~ s/.*\///;
	  print STDERR "\n$cmd: $mess\n";
	  exit 1;
	}
	');
}

# Always end library in 1
1;
