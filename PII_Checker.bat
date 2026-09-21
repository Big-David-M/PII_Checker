@echo off
title PII Checker
py "%~dp0pii_checker.py"
if errorlevel 1 (
    python "%~dp0pii_checker.py"
)
if errorlevel 1 (
    python3 "%~dp0pii_checker.py"
)
if errorlevel 1 (
    echo Python not found. Install Python 3.8+ from https://python.org
    pause
)
