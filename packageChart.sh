#!/bin/env bash

# This script is used to generate a chart

helm lint deploy/desec-webhook
helm package deploy/desec-webhook
helm repo index --url https://pr0ton11.github.io/cert-manager-desec-webhook/ .
