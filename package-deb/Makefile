PACKAGE=azure-cert-rotation
VERSION=0.9.0
FAKEROOT=./data-root
DOCDIR=$(FAKEROOT)/usr/share/doc/$(PACKAGE)/
LINTIANOVERRIDES=$(FAKEROOT)/usr/share/lintian/overrides/$(PACKAGE)
DEB=$(PACKAGE)_$(VERSION)_amd64.deb
BINDIR=$(FAKEROOT)/usr/bin
LIBDIR=$(FAKEROOT)/usr/local/lib/python3.5/dist-packages/azure_cert_rotation

package: $(DEB)

signed-package: _gpgorigin $(DEB)
	ar r $(DEB) $<

_gpgorigin: $(DEB)
	-rm -f $@
	ar p $(DEB) debian-binary control.tar.gz data.tar.gz | gpg -abs -o _gpgorigin

$(DEB): tarballs debian-binary
	-rm -f $@
	ar rc $@ debian-binary control.tar.gz data.tar.gz
	lintian $@

$(DOCDIR):
	mkdir -p $@
	install -m 644 ../sample.json $@
	install -m 644 ../requirements.txt $@

$(DOCDIR)/changelog.gz: changelog $(DOCDIR)
	cat $< | sed 's/PACKAGENAME/$(PACKAGENAME)/g' | sed 's/VERSION/$(VERSION)/g' | gzip -n -9 > $@

$(DOCDIR)/copyright: copyright $(DOCDIR)
	cp $< $@

$(LINTIANOVERRIDES): lintian-overrides
	mkdir -p $(@D)
	cat $< | sed "s/PACKAGE/$(PACKAGE)/g" >$@
	
debian-binary:
	echo 2.0 > debian-binary

tarballs: data.tar.gz control.tar.gz

control.tar.gz: md5sums control
	-rm -rf control-root
	-mkdir -p control-root	
	install -m 644 control md5sums control-root
	install -m 755 postinst control-root
	sed -i '/^Version:/c Version: $(VERSION)' control-root/control
	sed -i '/^Package:/c Package: $(PACKAGE)' control-root/control
	cd control-root && tar -czf ../$@ --owner=root --group=root .

md5sums: install-deps
	(cd $(FAKEROOT) && md5sum `find -type f`) > $@
	chmod 0644 $@

data.tar.gz: install-deps \
             $(DOCDIR)/changelog.gz \
             $(DOCDIR)/copyright \
			 $(LINTIANOVERRIDES)
	find $(FAKEROOT) -type d | xargs chmod 0755
	find $(FAKEROOT) -type d | xargs chmod ug-s
	find $(FAKEROOT)/usr/share/doc -type f | xargs chmod 0644
	cd $(FAKEROOT) && tar -czf ../$@ --owner=root --group=root --mode=go-w *

.PHONY: clean install-clean install-deps

clean: install-clean
	-rm -rf control-root
	-rm -f debian-binary *.tar.gz _gpgorigin md5sums
	-rm -f azure*.deb

install-clean:
	-rm -rf $(FAKEROOT)

install-deps: install-clean	
	mkdir -p $(BINDIR) ${LIBDIR}
	install -m 644 ../azure_cert_rotation/__init__.py $(LIBDIR)
	install -m 755 ../azure_cert_rotation/keyvault_client.py $(LIBDIR)
	install -m 755 ../azure_cert_rotation/rdfe_client.py $(LIBDIR)
	install -m 755 ../rotate_certs.py $(BINDIR)/rotate_certs
	
