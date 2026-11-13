SHELL     := /bin/bash
ENV       ?= dev
BACKEND   ?= $(ENV).gcs.tfbackend
# Optional override. When unset, Terraform uses `image` from terraform.tfvars.
IMAGE     ?=
IMAGE_ARG := $(if $(IMAGE),-var "image=$(IMAGE)",)

.PHONY: init plan apply destroy

init:
	@test -f "$(BACKEND)" || (echo "Missing $(BACKEND). Copy $(ENV).gcs.tfbackend.example to $(BACKEND) and fill in your bucket." && exit 1)
	terraform init -reconfigure -backend-config="$(BACKEND)"
	terraform workspace select $(ENV) || terraform workspace new $(ENV)

plan: init
	terraform plan $(IMAGE_ARG)

apply: init
	terraform apply $(IMAGE_ARG)

destroy: init
	terraform destroy $(IMAGE_ARG)
