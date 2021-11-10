TAG = latest
APP = $(shell basename $(CURDIR))
build:
	docker build -t registry.gitlab.exphost.pl/exphost/$(APP):$(TAG) .

push:
	docker push registry.gitlab.exphost.pl/exphost/$(APP):$(TAG)

run:
	docker run -it registry.gitlab.exphost.pl/exphost/$(APP):$(TAG)
