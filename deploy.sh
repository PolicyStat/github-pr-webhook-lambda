#!/bin/bash
DEPLOY_ENV=$(pwd)/.deploy
echo 'creating virtualenv' &&
rm -fR $DEPLOY_ENV &&
virtualenv --quiet $DEPLOY_ENV &&
export VIRTUAL_ENV=$DEPLOY_ENV
export PATH=$VIRTUAL_ENV/bin &&
echo 'installing requirements' &&
pip -q install -r requirements.txt &&
echo 'deploying to lambda' &&
zappa update &&
true
