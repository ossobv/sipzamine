PYTHON = $(shell which python)
SIPZAMINE = $(PYTHON) -m sipzamine

.PHONY: test flake8 run23 _run version

test: flake8 run23 version

flake8:
	$(shell which python2) -m flake8 sipzamine
	$(shell which python3) -m flake8 sipzamine

run23:
	$(RM) Makefile.out2 Makefile.err2
	$(MAKE) PYTHON=$(shell which python2) _run \
	    OUT=Makefile.out2 ERR=Makefile.err2
	$(RM) Makefile.out3 Makefile.err3
	$(MAKE) PYTHON=$(shell which python3) _run \
	    OUT=Makefile.out3 ERR=Makefile.err3
	diff -pu Makefile.out2 Makefile.out3
	diff -pu Makefile.err2 Makefile.err3
	mv Makefile.out3 Makefile.out; $(RM) Makefile.out2
	mv Makefile.err3 Makefile.err; $(RM) Makefile.err2
	#cat Makefile.err
	#cat Makefile.out
	$(RM) Makefile.out Makefile.err

_run:
	echo '== HELP ==' | tee -a "$(ERR)" >>"$(OUT)"
	$(SIPZAMINE) --help >>"$(OUT)" 2>>"$(ERR)"
	echo '== basic-match ==' | tee -a "$(ERR)" >>"$(OUT)"
	$(SIPZAMINE) \
	  samples/dtmf_2833_1.pcap \
	  samples/sip-invites-with-utf8-and-latin1.pcap \
	  -m '(1-26254|1-26272)@' -H 'From: "([^"]*)"' 2>>"$(ERR)" | \
	  tee -a "$(OUT)" | md5sum >>"$(ERR)"
	grep -q dc4ca5ee8dd057932ad42e0d589950ed "$(ERR)"
	echo '== contents ==' | tee -a "$(ERR)" >>"$(OUT)"
	$(SIPZAMINE) \
	  samples/dtmf_2833_1.pcap \
	  samples/sip-invites-with-utf8-and-latin1.pcap \
	  -m '(1-26254|1-26272)@' --contents 2>>"$(ERR)" | \
	  tee -a "$(OUT)" | md5sum >>"$(ERR)"
	grep -q 6ee0407d05eae93c0e953bfb7e720808 "$(ERR)"
	echo '== dateskew ==' | tee -a "$(ERR)" >>"$(OUT)"
	$(SIPZAMINE) \
	  samples/dtmf_2833_1.pcap \
	  samples/sip-invites-with-utf8-and-latin1.pcap \
	  --dateskew 59 --maxdate '2020-04-22 09:38:03' 2>>"$(ERR)" | \
	  tee -a "$(OUT)" | md5sum >>"$(ERR)"
	grep -q 0a36abde0ed8ffa641603b329bbb13cb "$(ERR)"
	echo '== p-none ==' | tee -a "$(ERR)" >>"$(OUT)"
	test $$($(SIPZAMINE) \
	  samples/dtmf_2833_1.pcap \
	  samples/sip-invites-with-utf8-and-latin1.pcap \
	  -p 'host 1.2.3.4' 2>>"$(ERR)" | wc -l) -eq 0
	echo '(no hits, as expected)' >>"$(OUT)"
	echo '== p-all ==' | tee -a "$(ERR)" >>"$(OUT)"
	test $$($(SIPZAMINE) \
	  samples/dtmf_2833_1.pcap \
	  samples/sip-invites-with-utf8-and-latin1.pcap \
	  -p 'host 127.0.1.254' 2>>"$(ERR)" | wc -l) -eq 40
	echo '(all hits, as expected)' >>"$(OUT)"

version:
	ver=$$(python -c 'import sipzamine; print sipzamine.__version__') && \
	git=$$(git describe) && \
	gitv=$$(echo "$$git" | sed -e 's/^v//;s/-.*/.post0/') && \
	setup=$$(sed -e "/version='/"'!d'";s/.*='\([^']*\)'.*/\1/" setup.py) \
	  && echo "ver = $$ver, setup = $$setup, git = $$gitv ($$git)" && \
	test $$ver = $$setup && \
	test $$ver = $$gitv


