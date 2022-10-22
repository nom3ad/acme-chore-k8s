GIT_COMMIT_SHA ?= $(shell git rev-parse --short HEAD)
BUILD_TIMESTAMP ?= $(shell date --utc --iso-8601=minutes)

.PHONY: run-image
run-image:
	@set -e; \
	tag=$${tag:-"acme-chore"}; \
	KUBECONFIG=$${KUBECONFIG:-"~/.kube/config"}; \
	config_mount_args=(); \
	while read -r kc; do [[ -f "$$kc" ]] && config_mount_args+=("--volume=$$kc:$$kc:ro"); done <<<"$${KUBECONFIG//:/$$'\n'}"; \
	PWD=$$(pwd); \
	if [[ -z $$DATA_DIR ]]; then DATA_DIR=$$PWD/data; mkdir -p $$DATA_DIR; fi; \
	set -x; \
	docker run -it --rm --net=host --name="acme-chore" "$${config_mount_args[@]}" $$DOCKER_ARGS -v $$PWD/main.sh:/main.sh:ro -v $$DATA_DIR:/data \
	-e DOMAINS \
	-e ACCOUNT_EMAIL \
	-e TLS_SECRET \
	-e CONFIG_MAP \
	-e NAMESPACE \
	-e UPDATE_BEFORE_DAYS \
	-e CHECK_INTERVAL \
	-e CA_SERVER \
	-e HTTP_SCHEME \
	-e DEBUG \
	-e PORT \
	-e KUBECONFIG \
	-e KUBECTL_CONTEXT \
	-e FORCE_RENEW \
	-e VALID_TO \
	-e KEY_LENGTH \
	$$tag

.PHONY: image
image:
	@set -e; \
	tag=$${tag:-"acme-chore"}; \
	docker build -t $$tag -f Dockerfile --build-arg GIT_COMMIT_SHA=$(GIT_COMMIT_SHA) --build-arg BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) .; \
	[[ -n $$push ]] || { read -p "Push (Y/n)?" && [[ $${REPLY,} == "y" ]]; } && docker push $$tag;

.PHONY: build-and-push-multi-arch-image
build-and-push-multi-arch-image:  
	@set -e; \
	tag=$${tag-"acme-chore"}; \
	docker buildx build --push --platform linux/arm64,linux/amd64 -t $$tag -f Dockerfile .;


apply-manifest:
	kubectl apply -f manifests.yaml 