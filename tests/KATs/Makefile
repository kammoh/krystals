
REFDIR=../kyber/ref

.PRECIOUS: $(REFDIR)/test_vectors%

kyber_%.kat: $(REFDIR)/test_vectors%
	$< > $@

$(REFDIR)/test_vectors%:
	$(MAKE) -C $(REFDIR) $(notdir $@)

all: kyber_1024.kat kyber_512.kat kyber_768.kat