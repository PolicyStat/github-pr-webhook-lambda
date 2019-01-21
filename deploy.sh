#!/bin/bash
echo 'creating virtualenv' &&
virtualenv --quiet .deploy &&
export PATH=$(pwd)/.deploy/bin &&
echo 'installing requirements' &&
pip -q install -r requirements.txt &&
echo 'deploying to lambda' &&
zappa update &&
true
