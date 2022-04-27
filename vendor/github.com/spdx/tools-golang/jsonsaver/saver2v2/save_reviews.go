// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"fmt"

	"github.com/spdx/tools-golang/spdx"
)

func renderReviews2_2(reviews []*spdx.Review2_2, jsondocument map[string]interface{}) ([]interface{}, error) {

	var review []interface{}
	for _, v := range reviews {
		rev := make(map[string]interface{})
		if len(v.ReviewDate) > 0 {
			rev["reviewDate"] = v.ReviewDate
		}
		if len(v.ReviewerType) > 0 || len(v.Reviewer) > 0 {
			rev["reviewer"] = fmt.Sprintf("%s: %s", v.ReviewerType, v.Reviewer)
		}
		if len(v.ReviewComment) > 0 {
			rev["comment"] = v.ReviewComment
		}
		if len(rev) > 0 {
			review = append(review, rev)
		}
	}
	if len(review) > 0 {
		jsondocument["revieweds"] = review
	}
	return review, nil
}
