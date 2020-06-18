#!/usr/bin/bash

set -e
eval "$(jq -r '@sh "project_id=\(.project_id)"')"

eval "hash=`gcloud container images describe gcr.io/$project_id/tokenclient --project=$project_id --format='value(image_summary.digest)'`"


jq -n --arg image_hash "$hash" '{"image_hash":$image_hash}'