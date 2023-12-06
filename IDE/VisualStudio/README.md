# Visual Studio Solution for wolfTPM

This includes projects for building wolfssl, wolftpm and some examples. The solution and project are based on older VS 2015, but can be retargeted / updated to newer when opened.

All build settings are contained in IDE/VisualStudio/user_settings.h. This module supports using the FIPS ready bundle from the website. Just enable the `#if 0` FIPS section in user_settings.h. See wolfssl/IDE/WIN10/README.txt for details on setting the FIPS integrity check in fips_test.c at run-time.

These projects assume `wolftpm` and `wolfssl` directories reside next to each other.
