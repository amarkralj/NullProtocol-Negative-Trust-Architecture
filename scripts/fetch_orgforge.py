# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Download the OrgForge-IT benchmark (MIT licence) into data/orgforge."""
from huggingface_hub import snapshot_download

snapshot_download("aeriesec/orgforge-insider-threat", repo_type="dataset", local_dir="data/orgforge")
print("downloaded to data/orgforge")
