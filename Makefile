verify_requirements:
	pip-compile-multi verify

update_requirements:
	pip-compile-multi --generate-hashes base --no-upgrade

upgrade_requirements:
	pip-compile-multi --generate-hashes base --upgrade

deploy: export VIRTUAL_ENV=$(shell pwd)/.deploy
deploy:
	@echo 'creating virtualenv'
	rm -fR "$(VIRTUAL_ENV)"
	virtualenv --quiet "$(VIRTUAL_ENV)"
	@echo 'installing requirements'
	"$(VIRTUAL_ENV)/bin/pip" --quiet install -r requirements.txt
	@echo 'deploying to lambda'
	"$(VIRTUAL_ENV)/bin/zappa" update

clean:
	rm *.zip
