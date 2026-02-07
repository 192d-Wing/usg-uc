#!/usr/bin/env bash
# Build and optionally push the GitLab CI Docker image

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
REGISTRY="${CI_REGISTRY:-registry.gitlab.com}"
PROJECT_PATH="${CI_PROJECT_PATH:-your-group/your-project}"
IMAGE_NAME="ci-image"
TAG="${CI_COMMIT_REF_SLUG:-latest}"

# Parse arguments
PUSH=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH=true
            shift
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --project)
            PROJECT_PATH="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --push              Push image to registry after building"
            echo "  --registry REGISTRY Set registry URL (default: registry.gitlab.com)"
            echo "  --project PATH      Set project path (default: your-group/your-project)"
            echo "  --tag TAG           Set image tag (default: latest)"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Build only"
            echo "  $0 --push                             # Build and push"
            echo "  $0 --push --tag v1.0.0                # Build and push with tag"
            echo "  $0 --project mygroup/myproject --push # Custom project"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Full image name
FULL_IMAGE="${REGISTRY}/${PROJECT_PATH}/${IMAGE_NAME}:${TAG}"

# Change to script directory
cd "$(dirname "$0")"

echo -e "${GREEN}=== Building CI Docker Image ===${NC}"
echo "Image: ${FULL_IMAGE}"
echo ""

# Build the image
echo -e "${YELLOW}Building...${NC}"
docker build -t "${FULL_IMAGE}" .

echo -e "${GREEN}✓ Build successful${NC}"
echo ""

# Also tag as 'latest' if tag is not 'latest'
if [ "$TAG" != "latest" ]; then
    LATEST_IMAGE="${REGISTRY}/${PROJECT_PATH}/${IMAGE_NAME}:latest"
    echo -e "${YELLOW}Tagging as latest...${NC}"
    docker tag "${FULL_IMAGE}" "${LATEST_IMAGE}"
    echo -e "${GREEN}✓ Tagged as ${LATEST_IMAGE}${NC}"
    echo ""
fi

# Push if requested
if [ "$PUSH" = true ]; then
    echo -e "${YELLOW}Pushing to registry...${NC}"
    docker push "${FULL_IMAGE}"
    echo -e "${GREEN}✓ Pushed ${FULL_IMAGE}${NC}"

    if [ "$TAG" != "latest" ]; then
        docker push "${LATEST_IMAGE}"
        echo -e "${GREEN}✓ Pushed ${LATEST_IMAGE}${NC}"
    fi
    echo ""
    echo -e "${GREEN}=== Complete ===${NC}"
    echo "Update .gitlab-ci.yml to use:"
    echo "  image: ${FULL_IMAGE}"
else
    echo -e "${YELLOW}=== Build Complete ===${NC}"
    echo "Image built locally: ${FULL_IMAGE}"
    echo ""
    echo "To push to registry, run:"
    echo "  $0 --push"
fi
