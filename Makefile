build_docker:
	docker build -t redirector -f Dockerfile.redirector .

run_docker:
	docker run -p 8080:8080 redirector