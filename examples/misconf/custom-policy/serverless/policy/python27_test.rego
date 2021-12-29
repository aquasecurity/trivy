package user.serverless.ID005

test_denied {
	msg = "Python 2.7 should not be the default provider runtime"
	deny[msg] with input as {
	    "service": "my-service",
	    "provider": {
	        "name": "kubeless",
	        "runtime": "python2.7",
	    }
	}
}

test_allowed {
	r := deny with input as {
	    "service": "my-service",
	    "provider": {
	        "name": "kubeless",
	        "runtime": "python3.6",
	    }
	}
	count(r) == 0
}
