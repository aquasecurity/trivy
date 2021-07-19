package user.compose.ID003

test_denied {
	r := deny with input as {
	    "version": "3.4",
	    "services": {
	        "web": {
	            "image": "nginx:1.21",
	            "ports": [{"8080:8080"}],
	        },
	        "db": {
	            "image": "mysql:latest",
	        },
	    }
	}

	count(r) == 1
	r[_] == "':latest' tag is not allowed"
}

test_allowed {
	r := deny with input as {
	    "version": "3.4",
	    "services": {
	        "web": {
	            "image": "nginx:1.21",
	            "ports": [{"8080:8080"}],
	        },
	        "web": {
	            "image": "mysql:5.6",
	        },
	    }
	}

	count(r) == 0
}
