#! /usr/bin/env bash
set -x

# setup
discussion_created_json="$1"
config_discussion_labels="$2"

discussion_category_name=$(jq -r '.category.name' "$discussion_created_json")
discussion_node_id=$(jq -r '.node_id' "$discussion_created_json")
discussion_body=$(jq -r '.body' "$discussion_created_json")

# find relavant labels in discussion
# trivy's discussion form asks for scanner and target as select boxes
if [ "$discussion_category_name" != 'Ideas' ]; then exit 0; fi
discussion_target=$(awk -v RS="\\\\n\\\\n" '/^### Target/ {getline; print;}' <<< "$discussion_body")
discussion_scanner=$(awk -v RS="\\\\n\\\\n" '/^### Scanner/ {getline; print;}' <<< "$discussion_body")
# find the corresponding labels for the selected options
label_target=$(awk -F: "/^$discussion_target/ "'{print $2}' <"$config_discussion_labels")
label_scanner=$(awk -F: "/^$discussion_scanner/ "'{print $2}' <"$config_discussion_labels")

# apply labels to discussion
addlabels_gql='mutation AddLabels($labelId: ID!, $labelableId:ID!) {
  addLabelsToLabelable(
    input: {labelIds: [$labelId], labelableId: $labelableId}
  ) {
    clientMutationId
  }
}'

if [ "$label_target" != "" ]; then
  gh api graphql -f query="$addlabels_gql" -f labelId="$label_target" -f labelableId="$discussion_node_id"
fi
if [ "$label_scanner" != "" ]; then
  gh api graphql -f query="$addlabels_gql" -f labelId="$label_scanner" -f labelableId="$discussion_node_id"
fi
