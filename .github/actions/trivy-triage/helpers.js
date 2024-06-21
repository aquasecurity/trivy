module.exports = {
    detectDiscussionLabels: (discussion, configDiscussionLabels) => {
        res = [];
        const discussionId = discussion.id;
        const category = discussion.category.name;
        const body = discussion.body;
        if (category !== "Ideas") {
            console.log(`skipping discussion with category ${category} and body ${body}`);
            return [];
        }
        const scannerPattern = /### Scanner\n\n(.+)/;
        const scannerFound = body.match(scannerPattern);
        if (scannerFound && scannerFound.length > 1) {
            res.push(configDiscussionLabels[scannerFound[1]]);
        }
        const targetPattern = /### Target\n\n(.+)/;
        const targetFound = body.match(targetPattern);
        if (targetFound && targetFound.length > 1) {
            res.push(configDiscussionLabels[targetFound[1]]);
        }
        return res;
    },
    fetchDiscussion: async (github, owner, repo, discussionNum) => {
        const query = `query Discussion ($owner: String!, $repo: String!, $discussion_num: Int!){
            repository(name: $repo, owner: $owner) {
                discussion(number: $discussion_num) {
                    number,
                    id,
                    body,
                    category {
                        id,
                        name
                    },
                    labels(first: 100) {
                        edges {
                            node {
                                id,
                                name
                            }
                        }
                    }
                }
            }
        }`;
        const vars = {
            owner: owner,
            repo: repo,
            discussion_num: discussionNum
        };
        return github.graphql(query, vars);
    },
    labelDiscussion: async (github, discussionId, labelIds) => {
        const query = `mutation AddLabels($labelId: ID!, $labelableId:ID!) {
            addLabelsToLabelable(
                input: {labelIds: [$labelId], labelableId: $labelableId}
            ) {
                clientMutationId
            }
        }`;
        // TODO: add all labels in one call
        labelIds.forEach((labelId) => {
            const vars = {
                labelId: labelId,
                labelableId: discussionId
            };
            github.graphql(query, vars);
        });
    }
};

