CXX ?= c++
MSBUILD ?= $(HOME)/.local/bin/msbuild
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror

.PHONY: all check check-config check-memory clean
all:
	$(MSBUILD) BlipLimitFix.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal

build/patch_test: tests/patch_test.cpp src/patch.hpp src/guard.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -Isrc $< -o $@

build/guard_test: tests/guard_test.cpp src/guard.hpp src/patch.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -Isrc $< -o $@

check: build/patch_test build/guard_test
	./build/patch_test
	./build/guard_test

check-config:
	$(MSBUILD) BlipLimitFix.vcxproj /p:Configuration=ConfigTest /p:Platform=x64 /v:minimal
	env WINEPREFIX="$(abspath build/wine-smoke)" WINEDEBUG=-all WINEDLLOVERRIDES=mscoree,mshtml=d wine build/config_test.exe

check-memory:
	$(MSBUILD) BlipLimitFix.vcxproj /p:Configuration=MemoryTest /p:Platform=x64 /v:minimal
	env WINEPREFIX="$(abspath build/wine-smoke)" WINEDEBUG=-all WINEDLLOVERRIDES=mscoree,mshtml=d wine build/memory_test.exe

clean:
	$(MSBUILD) BlipLimitFix.vcxproj /t:Clean /p:Configuration=Release /p:Platform=x64 /v:minimal
	$(MSBUILD) BlipLimitFix.vcxproj /t:Clean /p:Configuration=ConfigTest /p:Platform=x64 /v:minimal
	$(MSBUILD) BlipLimitFix.vcxproj /t:Clean /p:Configuration=MemoryTest /p:Platform=x64 /v:minimal
	rm -f dist/BlipLimitFix.ini build/patch_test build/guard_test
