IMAGE_TAG:=auser/redirector

.PHONY: build_docker run_docker test_docker build_docker_multiarch create_buildx_builder

create_buildx_builder:
	docker buildx create --name multiarch --use || true

build_docker:
	docker buildx build -t ${IMAGE_TAG} -f Dockerfile --load .

run_docker:
	docker run --rm -p 3001:3000 ${IMAGE_TAG}

# Add a test command to verify the container
test_docker:
	docker run -d --name redirector_test -p 3000:3000 ${IMAGE_TAG}
	sleep 2  # Wait for server to start
	curl -v http://localhost:3000/health
	docker logs redirector_test
	docker stop redirector_test
	docker rm redirector_test

build_docker_multiarch: create_buildx_builder
	docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target runtime \
  -t ${IMAGE_TAG} \
  -f Dockerfile \
  --push .
