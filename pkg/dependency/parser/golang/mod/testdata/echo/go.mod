module example.com/app

go 1.22.0

require (
	golang.org/x/net v0.55.0+echo.1
	example.com/replaced v1.3.4+echo.1
	example.com/mismatch v1.4.5+echo.1
	example.com/ordinary v1.5.6+build.1
	example.com/v2module/v2 v2.0.0+echo.1
)

replace (
	example.com/replaced v1.3.4+echo.1 => example.com/replacement v1.3.4+echo.2
	example.com/mismatch v1.4.5+echo.2 => example.com/not-used v1.4.5+echo.3
)

retract (
	master
	[master, release-branch]
)
