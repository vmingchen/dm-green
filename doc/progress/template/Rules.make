# -*- makefile -*-
# vim:filetype=make

# XXX: todo: ifeq 'anon' styles

ifeq ($(NAME),)
die:
	@echo "You did not specify a NAME."
	false
endif
ifeq ($(VENUE),)
die:
	@echo "You did not specify a VENUE."
	false
endif
ifeq ($(SRCS),)
die:
	@echo "You did not specify SRCS."
	false
endif

LATEX=./template/rlatex
PDFLATEX=pdflatex
BIBTEX=./template/rbibtex
PS_VIEWER=gv
PDF_VIEWER?=acroread
PROJLOC=$(HOME)/proj
BIBLOC=./template/master.bib
# NAME CAN BE "zen" and URLEXT can be "-tr"
URLTOP = $(PROJLOC)/www/docs/$(NAME)$(URLEXT)

# To generate a document with A4 paper size, set the a4paper option in
# the LaTeX documentclass and define A4PAPER to any value in the main
# Makefile.
# Alternatively, override DVIPSOPTS in the main Makefile to specify
# arbitrary options to dvips.
ifneq ($(A4PAPER),1)
#	DVIPSOPTS=-Pcmz -t letter -D 600
	DVIPSOPTS=-t letter -Ppdf -G0 -j0 -D 600
else
#	DVIPSOPTS=-Pcmz -t a4 -D 600
	DVIPSOPTS=-t a4 -Ppdf -G0 -j0 -D 600
endif

FIGS_SRC+=$(wildcard figures/*.fig)
VEC_FIGS_SRC+=$(wildcard vector-grafix/*.svg)
FIGS_EPS+=$(patsubst figures/%.fig, figures/%.eps, $(FIGS_SRC))
FIGS_EPS+=$(patsubst vector-grafix/%.svg, vector-grafix/%.eps, $(VEC_FIGS_SRC))
FIGS_PDF+=$(patsubst figures/%.fig, figures/%.pdf, $(FIGS_SRC))
FIGS_PDF+=$(patsubst vector-grafix/%.svg, vector-grafix/%.pdf, $(VEC_FIGS_SRC))

# We need to call plain LaTeX (without any script wrapper) once before
# the call to BibTeX.  Which LaTeX we use depends on whether
# USE_PDFLATEX is set.
ifeq ($(USE_PDFLATEX),1)
	PRELATEX=$(PDFLATEX)
	FIGS_PRE=$(FIGS_PDF)
else
	PRELATEX=latex
	FIGS_PRE=$(FIGS_EPS)
endif

BIBFILES=template/master.bib $(MYBIBFILES)
BBLFILES=$(NAME).bbl $(MYBBLFILES)
ifneq ($(wildcard bbl_contents_line.tex),)
BBLCONTENTSLINE=bbl_contents_line.tex
else
BBLCONTENTSLINE=template/bbl_contents_line.tex
endif

ifeq ($(ACM),1)
STYLES=	template/acmtrans2m.cls template/acmtrans.bst \
	template/acm_proc_article-sp.cls template/sig-alternate.cls \
	template/sig-alternate-tight.cls template/sigplan-proc.cls \
	$(MYSTYLES)
else
ifeq ($(CV),1)
STYLES=	template/bibunits.sty template/currvita.sty $(MYSTYLES)
EXTRAS+=multibib.date
else
STYLES=	template/usetex-v1.cls template/usetex-v1-anon.cls \
	template/usetex-v1-tight.cls template/fslreport.cls \
	$(MYSTYLES)
endif
endif

export TEXINPUTS=./template:
export BSTINPUTS=./template:
export BIBINPUTS=./template:

# Include paperdev.mk to override any variables that we've set
-include $(HOME)/.paperdev.mk
-include paperdev.mk

# The default Makefile target depends on whether we are using
# PDFLaTeX.
ifeq ($(USE_PDFLATEX),1)
all: $(NAME).pdf
else
all: $(NAME).ps
endif

figures/%.ps: figures/%.fig
	fig2dev -L ps $< $@

figures/%.eps: figures/%.fig
	fig2dev -L eps $< $@

figures/%.pdf: figures/%.fig
	fig2dev -L pdf $< $@

vector-grafix/%.eps: vector-grafix/%.svg
	inkscape -T --export-eps=$@ $<

vector-grafix/%.pdf: vector-grafix/%.svg
	inkscape -T $< --export-pdf=$@

data/%.eps: data/%.fig
	fig2dev -L eps $< $@

dvi: $(NAME).dvi
ps: $(NAME).ps
pdf: $(NAME).pdf

checkbib: FRC
	if which bibparse ; then bibparse template/master.bib ; fi

ifeq ($(ANON),1)

ANONFILES=template/master-anon.txt

$(NAME).bbl: $(BIBFILES) $(BBLCONTENTSLINE) $(FIGS_PRE) $(SRCS) tags
	$(PRELATEX) $(NAME).tex <&-
	$(BIBTEX) $(NAME)
	(head -1 $@ ; \
		cat $(BBLCONTENTSLINE) ; \
		( tail -n +2 $@ 2> /dev/null || tail +2 $@ ) ) > tmp_$@
	@echo 'Fix potential broken \url lines due to BibTeX...'
	perl -p -e "s:(/.*)%\n:\1:g" < tmp_$@ | perl template/anonymize.pl anonmap.txt $(ANONFILES) > $@
	rm -f tmp_$@
else
$(NAME).bbl: $(BIBFILES) $(BBLCONTENTSLINE) $(FIGS_PRE) $(SRCS) tags
	$(PRELATEX) $(NAME).tex <&-
	$(BIBTEX) $(NAME)
	(head -1 $@ ; \
		cat $(BBLCONTENTSLINE) ; \
		( tail -n +2 $@ 2> /dev/null || tail +2 $@ ) ) > tmp_$@
	@echo 'Fix potential broken \url lines due to BibTeX...'
	perl -p -e "s:(/.*)%\n:\1:g" < tmp_$@ > $@
	rm -f tmp_$@
endif

$(NAME).dvi: $(EXTRAS) $(FIGS_EPS) $(STYLES) $(BBLFILES) $(SRCS) Makefile tags
	$(LATEX) $(NAME).tex <&-

# use 600 DPI fonts and compress them (-Z)
$(NAME).ps: $(NAME).dvi
	dvips $(DVIPSOPTS) -o $@ $?
	@egrep '^%%Pages' $@
	@echo "Number of words is "`cat $(SRCS) | egrep -v '^[%\\]' | wc -w`
	@if [ -f abstract.tex ] ; then echo "Number of words in abstract is "`egrep -v '^[%\\]' abstract.tex | wc -w` ; fi

ifeq ($(USE_PDFLATEX),1)

# Using PDFLaTeX to generate PDF files is preferred, but we disable it
# by default, as some papers do not support it.
#
# To support PDFLaTeX, a paper must have PDF verions of all its
# figures, must use the \includegraphics command to include the
# figures, and must _not_ specify the extension the graphics file.
# (LaTeX infers the correct extension depending on whether it is
# generating a PDF or PS file.)
%.pdf: $(EXTRAS) $(FIGS_PDF) $(STYLES) $(BBLFILES) $(SRCS) Makefile tags
	LATEX_CMD="${PDFLATEX}" $(LATEX) $(NAME).tex <&-

else

%.pdf: %.ps
	ps2pdf14 -dEPSCrop $? || ps2pdf13 -dEPSCrop $? || ps2pdf -dEPSCrop $? || distill -noprefs < $? > $@ 2> /dev/null

endif

$(NAME).ascii: $(NAME).dvi
	dvi2tty -o $@ $?

show: show-dvi
show-dvi: $(NAME).dvi
	xdvi -paper us -s 0 -keep -nopostscript -geometry +0+0 $? -display $(DISPLAY)
show-ps: $(NAME).ps
	$(PS_VIEWER) $? -display $(DISPLAY) -geometry +0+0

ifeq ($(PDF_VIEWER),acroread)
show-pdf: $(NAME).pdf
	$(PDF_VIEWER) $? --display $(DISPLAY) -geometry +0+0
else

ifeq ($(PDF_VIEWER),open)
show-pdf: $(NAME).pdf
	${PDF_VIEWER} $?

else

show-pdf: $(NAME).pdf
	$(PDF_VIEWER) $? -display $(DISPLAY) -geometry +0+0
endif
endif



# update to latest TTH version supported/allowed
TTHVERS=3.85
html: $(NAME).html
$(NAME).html: $(SRCS)
	@echo Checking for TTH version ${TTHVERS}...
	@tth -h 2>&1 | grep -iq "version ${TTHVERS}"
	cp -p $(NAME).tex $(NAME).tex-SAVED
	sed 's/\\bibliographystyle{acmtrans}/\\bibliographystyle{plain}/g' < $(NAME).tex-SAVED > $(NAME).tex
	make dvi
	PATH=.:./template/:$(PATH) tth -e2 $(NAME).tex
	cp -p $(NAME).tex-SAVED $(NAME).tex
	rm -f $(NAME).tex-SAVED
	echo Fix URLs from latex2html/tth...
	perl -pni.orig -e 's,HREF="www,HREF="http://www,gi;' -e 's,HREF="ftp,HREF="ftp://ftp,gi' $(NAME).html

install-html: $(NAME).ps $(NAME).pdf $(NAME).html
	test -d $(URLTOP) || mkdir -p $(URLTOP)
	-rm -f $(URLTOP)/*
	chmod a+rx $(URLTOP)
	tar cf - $(NAME).html `find . -type f -name '*.png'` | (cd $(URLTOP) && tar xf -)
	cp $(URLTOP)/$(NAME).html $(URLTOP)/index.html
	chmod -R a+r $(URLTOP)
	install -c -m 644 $(NAME).ps $(URLTOP)/$(NAME).ps
	install -c -m 644 $(NAME).pdf $(URLTOP)/$(NAME).pdf

ALLTAR = $(SRCS) $(FIGS_EPS) $(EXTRAS) $(STYLES) \
	$(BIBFILES) $(BBLFILES) $(BBLCONTENTSLINE) \
	$(NAME).ps $(NAME).dvi $(NAME).pdf \
	Makefile $(LATEX) \
	template/Rules.make template/textags template/rbibtex

tar: $(ALLTAR)
	rm -fr ${NAME}-article
	mkdir ${NAME}-article
	tar czvf ${NAME}-files.tar.gz $(ALLTAR)
	(cd ${NAME}-article && tar zxvf ../${NAME}-files.tar.gz)
	tar czvf ${NAME}-files.tar.gz ${NAME}-article
	rm -fr ${NAME}-article

tartest: tar
	rm -fr ${NAME}-article
	tar xzvf ${NAME}-files.tar.gz
	(cd ${NAME}-article && make clean && make pdf)

checkdup: $(SRCS)
	double-word $(SRCS)

submit:: pdf
	cp -p $(NAME).pdf $(NAME)-SUBMITTED-TO-$(VENUE).pdf

crc:: pdf
	cp -p $(NAME).pdf $(NAME)-$(VENUE)-CRC.pdf

# rules for spliting a proposal into main text and bibliography
submit-proposal: submit-main.pdf submit-bib.pdf
submit-main.ps: $(NAME).ps
	psselect -p1-15 $? $@
submit-bib.ps: $(NAME).ps
	psselect -p16-99 $? $@

clean: FRC
	$(RM) $(RMFLAGS) *~ .*~ \#* core
	$(RM) $(RMFLAGS) *.dvi $(NAME).ps temp.ps *.lj *.lj4 $(NAME).bbl
	$(RM) $(RMFLAGS) $(NAME).ttt $(NAME).fff $(NAME).pdf $(NAME).txt
	$(RM) $(RMFLAGS) *.log *.aux *.toc *.lof *.blg *.lot *.cb
	$(RM) $(RMFLAGS) slides2.ps slides4.ps
	$(RM) $(RMFLAGS) data/*.eps data/*.fig
	$(RM) $(RMFLAGS) $(FIGS_EPS) anonmap.txt ${EXTRACLEAN}
	$(RM) $(RMFLAGS) tags

$(NAME).toc.txt: $(NAME).toc
	cat $(NAME).toc | \
		sed 's/\\contentsline //' | \
		sed 's/{\\numberline //' | \
		sed 's/{chapter}//' | \
		sed 's/{section}/\t/' | \
		sed 's/{subsection}/\t\t/' | \
		sed 's/{subsubsection}/\t\t\t/' | \
		sed 's/{paragraph}/\t\t\t\t/' | \
		sed 's/\\xspace//' | \
		sed 's/{\|}\|\$$/ /g' > $@

realclean: clean
	$(RM) $(RMFLAGS) *.bib *.bbl

spell:
	for s in $(SRCS); do ispell $$s; done

check:  checkbib consistify

consistify:
	perl template/consistify ${SRCS}

newcheck: checkbib
	perl template/consistify template/local-vars.tex $(filter ${SRCS}, $(shell cvs -qn update | grep -E '^(M|A)' | cut -d' ' -f 2))

# This rule is used to create several bibunit aux files
multibib.date: template/master.bib ${SRCS}
	-$(LATEX) $(NAME).tex <&-
	for i in bu*.aux; do bibtex -min-crossrefs=999 `basename $$i .aux`;done
	date > multibib.date

tags: template/master.bib $(SRCS) template/textags
	./template/textags template/master.bib $(SRCS)

# Using sed we ignore anything on a line that has '\epsfig' on it or '[(htpd!)+]'
abc: $(SRCS)
	for F in $(SRCS); do \
		echo "===== $$F:"; \
		echo "personal_ws-1.1 en 100" > .aspell.en.$$F.pws; \
		sed -n "/^% LocalWords:/{s/^% LocalWords:[ \t]*//;s/[ \t][ \t]*/\n/g;p}" < $$F | sed "/^$$/ d" >> .aspell.en.$$F.pws; \
		cat template/latex-spell-words >> .aspell.en.$$F.pws; \
		sed -n "/\\\\epsfig/!p" < $$F | sed -n "/\[[htpb!][htpb!]*\]/!p" | \
	aspell list -t --personal=./.aspell.en.$$F.pws | sort | uniq; \
	rm .aspell.en.$$F.pws; \
	done;

# Include extra-rules.mk to add your personal rules
-include $(HOME)/.extra-rules.mk
-include extra-rules.mk

FRC:

