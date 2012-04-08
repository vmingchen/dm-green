-include local1.inc

all: checkbib consistify extractbib

checkbib:
	bibparse master.bib

consistify: FRC
	perl -c consistify
extractbib: FRC
	perl -c extractbib

-include local2.inc

FRC:
