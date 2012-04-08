: # *-*-perl-*-*
    eval 'exec perl -S  $0 "$@"'
    if $running_under_some_shell;

# script to anonymize bibtex items
# usage: anonymize.pl anonmap [anonlist ...]
# Where: anonmap is a txt file that will be written to include the fully
#	 expanded list of anonymized entries; and anonlist is a list of
#	 files that contain bib index names to be anonymized.
#
use Data::Dumper;
use Text::Wrap;

my %anonitems = ();
my $anonmap = shift;
die "$0 anonmap [anonlist ...]" if (!defined($anonmap));

open(ANONMAP, ">$anonmap") || die "open: $!\n";

while ($_ = shift(@ARGV)) {
	open(ANON, $_);
	map { chomp; $anonitems{$_} = 1; } (<ANON>);
	close(ANON);
}

my $entry = 0;
while (<>) {
	if (/^\\bibitem\{(.*)\}$/) {
		$entry++;
		if ($anonitems{$1}) {
			print $_;
			print "Elided for review.\n\n";

			# Now create the anonymous entry
			$str = "[$entry] ";

			while (<>) {
				chomp;
				last if /^$/;
				$str .= $_;
			}

			$str =~ s/~/ /g;
			$str =~ s/\\newblock//g;
			$str =~ s/\\[a-z]+{(.*?)}/$1/g;
			$str =~ s/{\\\w+\s+(.*?)}/$1/g;
			$str =~ s/{(.*?)}/$1/g;

			print ANONMAP wrap("", "  ", $str) . "\n\n";
			next;
		}
	}
	print;
}

close(ANONMAP);

