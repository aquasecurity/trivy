const patterns = {
    Scanner: /### Scanner\r?\n\r?\n(.+)/,
    Target: /### Target\r?\n\r?\n(.+)/,
};

module.exports = {
    detectDiscussionLabels: (discussion, configDiscussionLabels) => {
        const res = [];
        const discussionId = discussion.id;
        const category = discussion.category.name;
        const body = discussion.body;
        if (category !== "Ideas") {
            console.log(`skipping discussion with category ${category} and body ${body}`);
            return [];
        }

        for (const key in patterns) {
            const match = body.match(patterns[key]);
            if (match && match.length > 1 && match[1] !== "None") {
                const val = configDiscussionLabels[match[1]];
                if (val === undefined && match[1]) {
                    console.warn(
                        `Value for ${key.toLowerCase()} key "${
                            match[1]
                        }" not found in configDiscussionLabels`
                    );
                } else {
                    res.push(val);
                }
            }
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

