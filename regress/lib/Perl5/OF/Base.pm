#############################################################
# $Id: Base.pm 3161 2007-12-13 21:08:05Z grg $
#
# Module provides basic functions for use by OF Perl scripts.
#
# Revisions:
#
##############################################################

package OF::Base;

use Exporter;
@ISA    = ('Exporter');
@EXPORT = qw( &check_OF_vars_set
);

##############################################################
#
# Check that the user has set up their environment correctly.
#
##############################################################
sub check_OF_vars_set {

	my @of_vars = qw(OFT_ROOT OF_ROOT);

	for (@of_vars) {
		my_die("Please set shell variable $_ and try again.")
		  unless defined $ENV{$_};
	}

}

##############################################################
#
# Define a my_die function if it doesn't already exist
#
##############################################################

if ( !defined(&my_die) ) {
	eval( '
	  sub my_die {
	  my $mess = shift @_;
	  (my $cmd = $0) =~ s/.*\///;
	  print STDERR "\n$cmd: $mess\n";
	  exit 1;
	}
	' );
}

# Always end library in 1
1;
