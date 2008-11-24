#!/usr/bin/perl -W
# Script to automatically download, make, and install required Perl modules 
# for OpenFlow regression tests.

use strict;
use File::Basename;

my @module_paths = (
	'http://search.cpan.org/CPAN/authors/id/S/SA/SAPER/Net-Pcap-0.14.tar.gz',
	'http://search.cpan.org/CPAN/authors/id/S/SZ/SZABGAB/Net-RawIP-0.21.tar.gz',
	'http://search.cpan.org/CPAN/authors/id/M/MH/MHX/Convert-Binary-C-0.71.tar.gz',
	'http://search.cpan.org/CPAN/authors/id/F/FT/FTASSIN/Data-HexDump-0.02.tar.gz',
);

mkdir "perl_modules";
chdir "perl_modules";

foreach my $path (@module_paths) {
	`wget $path`;
    my $module = fileparse($path);
	`tar xzf $module`;
	$module =~ s/.tar.gz//;
	print "compiling $module\n";
	chdir $module;
	print `perl Makefile.PL`;
	print `make`;
	print `make install`;
	chdir '../';
}

print "finished\n";

