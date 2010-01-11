mod_memc_sess.la: mod_memc_sess.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_memc_sess.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_memc_sess.la
