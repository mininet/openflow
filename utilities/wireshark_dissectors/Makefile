# simple Makefile to build and install all of our Wireshark plugins

# build a list of all sub-directories except the includes path
PLUGIN_DIRS = $(shell ls -l | grep "^d" | cut -d: -f2- | cut -d\  -f2 | fgrep -v 'wireshark-1.0.0-includes')
CLEAN_PLUGIN_DIRS = $(foreach dir,$(PLUGIN_DIRS),clean$(dir))
INSTALL_PLUGIN_DIRS = $(foreach dir,$(PLUGIN_DIRS),install$(dir))

.PHONY: all $(PLUGIN_DIRS) clean $(CLEAN_PLUGIN_DIRS) install $(INSTALL_PLUGIN_DIRS)

# build all the plugins
all:
	@$(MAKE) --no-print-directory $(PLUGIN_DIRS)

# cleanup all the byproducts (including the plugin itself)
clean:
	@$(MAKE) --no-print-directory $(CLEAN_PLUGIN_DIRS)

# install all plugins
install:
	@$(MAKE) --no-print-directory $(INSTALL_PLUGIN_DIRS)

# build the plugin in the specified directory using its default rule
$(PLUGIN_DIRS):
	@$(MAKE) --no-print-directory -C $@

# cleans up the plugin in the specified directory using its 'clean' rule
$(CLEAN_PLUGIN_DIRS):
	@$(MAKE) --no-print-directory -C `echo $@ | sed -e "s#^clean##"` clean

# installs up the plugin in the specified directory using its 'install' rule
$(INSTALL_PLUGIN_DIRS):
	@$(MAKE) --no-print-directory -C `echo $@ | sed -e "s#^install##"` install
