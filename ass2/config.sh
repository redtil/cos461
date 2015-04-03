#!/bin/bash
cd pox_module
python2.7 setup.py develop
cd ../ltprotocol
python2.7 setup.py install
pkill -9 sr_solution
pkill -9 sr

