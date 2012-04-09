# The customizations for this particular paper
NAME=	main
VENUE=	CONF2012
SRCS=	$(NAME).tex		\
	abstract.tex		\
	intro.tex		\
	bg.tex			\
	design.tex		\
	implementation.tex	\
	eval.tex		\
	related.tex		\
	conclusion.tex		\
	ack.tex

# extre dependencies
EXTRAS=smr.bib figures/*.eps

# Let the user have custom overrides, globally or for just this paper.
-include $(HOME)/.paperdev.mk
-include paperdev.mk

# Use the default Make rules
-include template/Rules.make
