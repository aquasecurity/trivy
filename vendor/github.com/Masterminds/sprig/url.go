package sprig

import (
	"fmt"
	"net/url"
	"reflect"
)

func dictGetOrEmpty(dict map[string]interface{}, key string) string {
	value, ok := dict[key]; if !ok {
		return ""
	}
	tp := reflect.TypeOf(value).Kind()
	if tp != reflect.String {
		panic(fmt.Sprintf("unable to parse %s key, must be of type string, but %s found", key, tp.String()))
	}
	return reflect.ValueOf(value).String()
}

// parses given URL to return dict object
func urlParse(v string) map[string]interface{} {
	dict := map[string]interface{}{}
	parsedUrl, err := url.Parse(v)
	if err != nil {
		panic(fmt.Sprintf("unable to parse url: %s", err))
	}
	dict["scheme"]    = parsedUrl.Scheme
	dict["host"]      = parsedUrl.Host
	dict["hostname"]  = parsedUrl.Hostname()
	dict["path"]      = parsedUrl.Path
	dict["query"]     = parsedUrl.RawQuery
	dict["opaque"]    = parsedUrl.Opaque
	dict["fragment"]  = parsedUrl.Fragment
	if parsedUrl.User != nil {
		dict["userinfo"]  = parsedUrl.User.String()
	} else {
		dict["userinfo"] = ""
	}

	return dict
}

// join given dict to URL string
func urlJoin(d map[string]interface{}) string {
	resUrl := url.URL{
		Scheme:   dictGetOrEmpty(d, "scheme"),
		Host:     dictGetOrEmpty(d, "host"),
		Path:     dictGetOrEmpty(d, "path"),
		RawQuery: dictGetOrEmpty(d, "query"),
		Opaque:   dictGetOrEmpty(d, "opaque"),
		Fragment: dictGetOrEmpty(d, "fragment"),

	}
	userinfo := dictGetOrEmpty(d, "userinfo")
	var user *url.Userinfo = nil
	if userinfo != "" {
		tempUrl, err := url.Parse(fmt.Sprintf("proto://%s@host", userinfo))
		if err != nil {
			panic(fmt.Sprintf("unable to parse userinfo in dict: %s", err))
		}
		user = tempUrl.User
	}

	resUrl.User = user
	return resUrl.String()
}
