DIRS	= src

all : build

build : 
	-for d in $(DIRS); do (cd $$d; $(MAKE) ); done

clean : 
	-for d in $(DIRS); do (cd $$d; $(MAKE) clean ); done

install : 
	-for d in $(DIRS); do (cd $$d; $(MAKE) install ); done

remove : 
	-for d in $(DIRS); do (cd $$d; $(MAKE) remove ); done
