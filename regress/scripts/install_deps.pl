#!/usr/bin/perl -W
#
# Script to automatically install dependencies for regression tests

use strict;
use File::Basename;
use File::Path;
use Getopt::Std;
use Cwd;

use constant {
	UBUNTU  => 'Ubuntu',
	DEBIAN  => 'Debian',
	REDHAT  => 'RedHat',
	FEDORA  => 'Fedora',

	UNKNOWN  => 'unknown',
	X86_64  => 'x86_64',
};

# Executables
my $lsb_release = 'lsb_release';
my $apt_get = 'apt-get';
my $yum = 'yum';
my $uname = '/bin/uname';

my $distro;
my $machine;
my $sim;
my %install_funcs = (
	'Ubuntu'  => \&install_ubuntu_debian,
	'Debian'  => \&install_ubuntu_debian,
	'Fedora'  => \&install_fedora,
);
our($opt_s, $opt_d);

# Verify that this script is being run as root
if ($> != 0) {
	die "This script must be run as root";
}

# Parse the command line arguments
parse_args();


# Identify the distribution and machine
if (!defined($distro)) {
	identify_distro();
	die "Unable to identify the distribution" if (!defined($distro));
}
identify_machine();

# Call the appropriate install function
if ($install_funcs{$distro}) {
	$install_funcs{$distro}->();
}
else {
	die "Unable to find the install function for '$distro'";
}

exit 0;

#==========================================================

#
# identify_distro:
#   Attempt to identify the Linux distro
#
sub identify_distro {
	# First, look for lsb release which makes querying easier
	$lsb_release = `which $lsb_release`;
	chomp($lsb_release);
	if ( $? >> 8 == 0) {
		$distro = `$lsb_release -s -i`;
		chomp($distro);
		SWITCH: for ($distro) {
			/Ubuntu/ && do {
				$distro = UBUNTU;
				last SWITCH;
			};

			/Debian/ && do {
				$distro = DEBIAN;
				last SWITCH;
			};

			(/CentOS/ || /RedHat/) && do {
				$distro = REDHAT;
				last SWITCH;
			};

			/Fedora/ && do {
				$distro = FEDORA;
				last SWITCH;
			};

			# DEFAULT
			warn "Unknown Linux distro '$distro'";
			$distro = undef;
		}
	}

	# Otherwise, fall back to looking for release/version files in /etc
	else {
		if ( -f '/etc/debian_version' || -f '/etc/debian_release' ) {
			$distro = DEBIAN;
		}
		elsif ( -f '/etc/fedora-release') {
			$distro = FEDORA;
		}
		elsif ( -f '/etc/redhat-release' || -f '/etc/redhat_release' ) {
			$distro = REDHAT;
		}
	}
}

#
# identify_machine:
#   Attempt to identify the machine type
#
sub identify_machine {
	# First, look for lsb release which makes querying easier
	if ( -x $uname) {
		$machine = `$uname -m`;
		chomp($machine);
	}

	# we don't know what sort of machine this is
	else {
		$machine = UNKNOWN;
	}
}

#
# install_ubuntu_debian:
#   Install the necessary dependencies for Ubuntu and Debian
#
sub install_ubuntu_debian {
	my @pkgs = (
		'liberror-perl',
		'libio-interface-perl',
		'liblist-moreutils-perl',
		'libpcap0.8-dev',
		'iproute',
		'psmisc',
		'libnet-pcap-perl',
		'libnet-rawip-perl',
		'wget',
	);
	if ($machine eq X86_64) {
		push (@pkgs, 'libc6-dev-i386', 'ia32-libs');
	}

	my @modules = (
		'http://search.cpan.org/CPAN/authors/id/F/FT/FTASSIN/Data-HexDump-0.02.tar.gz',
		'http://www.cpan.org/authors/id/J/JV/JV/Getopt-Long-2.38.tar.gz',
	);

	if ($distro eq UBUNTU) {
		push (@pkgs, 'libconvert-binary-c-perl')
	}
	else {
		push (@modules,
			'http://search.cpan.org/CPAN/authors/id/M/MH/MHX/Convert-Binary-C-0.74.tar.gz')
	}

	# Run apt-get
	my @flags = ('-y');
	push(@flags, '-s') if defined($sim);
	system($apt_get, @flags, 'install', @pkgs);
	if ($? >> 8 != 0) {
		die "Error running $apt_get";
	}

	# Install modules directly from CPAN
	install_perl_modules(@modules);
}

#
# install_fedora:
#   Install the necessary dependencies for Fedora Core
#
sub install_fedora {
	my @pkgs = (
		'perl-Convert-Binary-C',
		'perl-Data-HexDump',
		'perl-Net-Pcap',
		'perl-Error.noarch',
		'perl-Module-Build',
		'libpcap-devel',
		'perl-List-MoreUtils',
		'perl-Net-RawIP',
	);

	# Run yum
	my @flags = ('-y');
	if (defined($sim)) {
		push(@flags, 'info');
	}
	else {
		push(@flags, 'install');
	}
	system($yum, @flags, @pkgs);
	if ($? >> 8 != 0) {
		die "Error running $yum";
	}
}

#
# install_perl_modules:
#   Fetch and install PERL modules
#
sub install_perl_modules {
	my @modules = @_;

	my $dir = "perl_modules";

	mkdir $dir;
	chdir $dir;

	foreach my $path (@modules) {
		`wget $path`;
		my $module = fileparse($path);
		`tar xzf $module`;
		$module =~ s/.tar.gz//;
		print "compiling $module\n";
		chdir $module;
		if (!defined($sim)) {
			system 'perl Makefile.PL';
			system 'make';
			system 'make install';
		}
		chdir '../';
	}

	chdir '..';
	rmtree $dir;
}

#
# parse_args
#   Parse the command line arguments
#
sub parse_args {
	getopts('sd:');
	$sim = 1 if defined($opt_s);
	$distro = $opt_d if defined($opt_d);
}

sub HELP_MESSAGE {
	print <<USAGE;
Usage:
    $0 [-s] [-d distro]

where
    -s   Run the utility in simulation mode

    -d distro
         Specify the distro instead of trying to identify it. Known distros:
USAGE

	print "           " . join(', ', sort(keys(%install_funcs))) . "\n";
	exit 0;
}
