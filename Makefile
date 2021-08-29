build:
	docker build -t registry.home.exphost.pl/exphost/password-generator .

push:
	docker push registry.home.exphost.pl/exphost/password-generator

run:
	docker run -it registry.home.exphost.pl/exphost/password-generator
