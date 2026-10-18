CXX ?= c++
MSBUILD ?= $(HOME)/.local/bin/msbuild
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror

.PHONY: all check check-config clean
all:
	$(MSBUILD) BlipLimitFix.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal

build/patch_test: tests/patch_test.cpp src/patch.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -Isrc $< -o $@

check: build/patch_test
	./build/patch_test

check-config:
	$(MSBUILD) BlipLimitFix.vcxproj /p:Configuration=ConfigTest /p:Platform=x64 /v:minimal
	env WINEPREFIX="$(abspath build/wine-smoke)" WINEDEBUG=-all WINEDLLOVERRIDES=mscoree,mshtml=d wine build/config_test.exe

clean:
	$(MSBUILD) BlipLimitFix.vcxproj /t:Clean /p:Configuration=Release /p:Platform=x64 /v:minimal
	$(MSBUILD) BlipLimitFix.vcxproj /t:Clean /p:Configuration=ConfigTest /p:Platform=x64 /v:minimal
	rm -f dist/BlipLimitFix.ini build/patch_test
