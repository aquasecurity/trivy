// Copyright 2018 Twitch Interactive, Inc.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not
// use this file except in compliance with the License. A copy of the License is
// located at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
package twirp

import (
	"context"
)

// Interceptor is a form of middleware for Twirp requests, that can be installed on both
// clients and servers. To intercept RPC calls in the client, use the option
// `twirp.WithClientInterceptors` on the client constructor. To intercept RPC calls in the server,
// use the option `twirp.WithServerInterceptors` on the server constructor.
//
// Just like http middleware, interceptors can mutate requests and responses.
// This can enable some powerful integrations, but it should be used with much care
// because it may result in code that is very hard to debug.
//
// Example of an interceptor that logs every request and response:
//
//   func LogInterceptor(l *log.Logger) twirp.Interceptor {
//     return func(next twirp.Method) twirp.Method {
//       return func(ctx context.Context, req interface{}) (interface{}, error) {
//         l.Printf("Service: %s, Method: %s, Request: %v",
//             twirp.ServiceName(ctx), twirp.MethodName(ctx), req)
//         resp, err := next(ctx, req)
//         l.Printf("Response: %v, Error: %v", resp)
//         return resp, err
//       }
//     }
//   }
//
type Interceptor func(Method) Method

// Method is a generic representation of a Twirp-generated RPC method.
// It is used to define Interceptors.
type Method func(ctx context.Context, request interface{}) (interface{}, error)

// ChainInterceptors chains multiple Interceptors into a single Interceptor.
// The first interceptor wraps the second one, and so on.
// Returns nil if interceptors is empty. Nil interceptors are ignored.
func ChainInterceptors(interceptors ...Interceptor) Interceptor {
	filtered := make([]Interceptor, 0, len(interceptors))
	for _, interceptor := range interceptors {
		if interceptor != nil {
			filtered = append(filtered, interceptor)
		}
	}
	switch n := len(filtered); n {
	case 0:
		return nil
	case 1:
		return filtered[0]
	default:
		first := filtered[0]
		return func(next Method) Method {
			for i := len(filtered) - 1; i > 0; i-- {
				next = filtered[i](next)
			}
			return first(next)
		}
	}
}
