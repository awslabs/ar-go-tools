#!/bin/sh
. .venv/bin/activate
cp payload/amazon-ssm-agent-check/checks_driver.py amazon-ssm-agent/checks_driver.py
cd amazon-ssm-agent
python checks_driver.py
