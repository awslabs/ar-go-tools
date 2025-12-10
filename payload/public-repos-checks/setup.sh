#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/configs"

# Repository configurations (name:url pairs)
REPOS="
amazon-cloudwatch-agent:git@github.com:aws/amazon-cloudwatch-agent.git
atlas:git@github.com:ariga/atlas.git
badger:git@github.com:dgraph-io/badger.git
cli:git@github.com:cli/cli.git
go-css:https://github.com/napsy/go-css
gogs:git@github.com:gogs/gogs.git
govatar:git@github.com:o1egl/govatar.git
ofxgo:git@github.com:aclindsa/ofxgo.git
photoprism:git@github.com:photoprism/photoprism.git
prometheus:git@github.com:prometheus/client_golang.git
rclone:git@github.com:rclone/rclone.git
ticker:git@github.com:achannarasappa/ticker.git
tidb:git@github.com:pingcap/tidb.git
v2ray-core:git@github.com:v2fly/v2ray-core.git
"

get_config_path() {
    case "$1" in
        "atlas") echo "cmd/atlas/argot-config.yaml" ;;
        *) echo "argot-config.yaml" ;;
    esac
}

clone_repos() {
    echo "Cloning repositories..."
    echo "$REPOS" | while IFS=: read -r repo url; do
        [ -z "$repo" ] && continue
        if [ ! -d "$repo" ]; then
            echo "Cloning $repo..."
            git clone "$url" "$repo"
        else
            echo "$repo already exists, skipping clone"
        fi
        mkdir -p "$repo/logs/argot"
    done
}

deploy_configs() {
    echo "Deploying configurations..."
    for config_file in "$CONFIGS_DIR"/*.yaml; do
        if [ -f "$config_file" ]; then
            repo_name=$(basename "$config_file" .yaml)
            if [ -d "$repo_name" ]; then
                config_path=$(get_config_path "$repo_name")
                target_dir="$repo_name/$(dirname "$config_path")"
                mkdir -p "$target_dir"
                cp "$config_file" "$repo_name/$config_path"
                echo "Deployed config to $repo_name/$config_path"
            fi
        fi
    done
}

sync_back() {
    echo "Syncing configurations back from repositories..."
    echo "$REPOS" | while IFS=: read -r repo url; do
        [ -z "$repo" ] && continue
        if [ -d "$repo" ]; then
            config_path=$(get_config_path "$repo")
            if [ -f "$repo/$config_path" ]; then
                cp "$repo/$config_path" "$CONFIGS_DIR/$repo.yaml"
                echo "Synced back config from $repo"
            fi
        fi
    done
}

case "${1:-setup}" in
    "setup")
        clone_repos
        deploy_configs
        echo "Setup complete!"
        ;;
    "sync-back")
        sync_back
        echo "Sync back complete!"
        ;;
    *)
        echo "Usage: $0 [setup|sync-back]"
        echo "  setup     - Clone repositories and deploy configs (default)"
        echo "  sync-back - Copy configs back from repositories to configs folder"
        exit 1
        ;;
esac
