TARGETS=repl-python.build repl-swift.build repl-nodejs.build

all: $(TARGETS)

.PHONY: clean deploy

repl-%.build: repl-%/Dockerfile repl-%/run.sh
	docker build -t repl-$* repl-$*
	touch $@

repl-%.tar: repl-%.build
	-rm $@
	docker save -o $@ repl-$*

clean:
	rm -f $(TARGETS)
	rm -f repl-*.tar
