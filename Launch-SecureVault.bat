@echo off
title SecureVault Launcher
:: Open index.html in a standalone, frameless desktop app window using Edge/Chrome
start msedge --app="file:///%~dp0index.html"
