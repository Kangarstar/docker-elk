#!/bin/bash

STACK_NAME="elk"

echo "🧹 Removing Docker stack: $STACK_NAME"
docker stack rm "$STACK_NAME"

echo "⏳ Waiting for all containers to be removed..."
# Wait until no containers (any state) with the stack label exist
while docker container ls -a --filter "label=com.docker.stack.namespace=$STACK_NAME" --format '{{.ID}}' | grep -q .; do
    echo "⌛ Still waiting for containers to be removed..."
    sleep 2
done

echo "✅ All containers for stack '$STACK_NAME' have been removed."

echo "🔍 Finding volumes associated with stack '$STACK_NAME'..."
VOLUMES=$(docker volume ls --format '{{.Name}}' | grep "^${STACK_NAME}_")

if [ -z "$VOLUMES" ]; then
    echo "✅ No volumes found for stack '$STACK_NAME'."
else
    echo "🗑 Removing volumes:"
    echo "$VOLUMES" | xargs -r docker volume rm
    echo "✅ Volumes removed."
fi
