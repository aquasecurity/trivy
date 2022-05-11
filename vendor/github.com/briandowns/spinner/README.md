# Spinner

[![GoDoc](https://godoc.org/github.com/briandowns/spinner?status.svg)](https://godoc.org/github.com/briandowns/spinner) [![Build Status](https://travis-ci.org/briandowns/spinner.svg?branch=master)](https://travis-ci.org/briandowns/spinner)

spinner is a simple package to add a spinner / progress indicator to any terminal application. Examples can be found below as well as full examples in the examples directory.

For more detail about the library and its features, reference your local godoc once installed.

Contributions welcome!

## Installation

```bash
go get github.com/briandowns/spinner
```

## Available Character Sets
(Numbered by their slice index)

| index | character set                                                                                                                                                                                                                                                                             | sample gif                 |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| 0     | ```←↖↑↗→↘↓↙```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/0.gif)  |
| 1     | ```▁▃▄▅▆▇█▇▆▅▄▃▁```                                                                                                                                                                                                                                                                       | ![Sample Gif](gifs/1.gif)  |
| 2     | ```▖▘▝▗```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/2.gif)  |
| 3     | ```┤┘┴└├┌┬┐```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/3.gif)  |
| 4     | ```◢◣◤◥```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/4.gif)  |
| 5     | ```◰◳◲◱```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/5.gif)  |
| 6     | ```◴◷◶◵```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/6.gif)  |
| 7     | ```◐◓◑◒```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/7.gif)  |
| 8     | ```.oO@*```                                                                                                                                                                                                                                                                               | ![Sample Gif](gifs/8.gif)  |
| 9     | ```\|/-\```                                                                                                                                                                                                                                                                               | ![Sample Gif](gifs/9.gif)  |
| 10    | ```◡◡⊙⊙◠◠```                                                                                                                                                                                                                                                                              | ![Sample Gif](gifs/10.gif) |
| 11    | ```⣾⣽⣻⢿⡿⣟⣯⣷```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/11.gif) |
| 12    | ```>))'> >))'>  >))'>   >))'>    >))'>   <'((<  <'((< <'((<```                                                                                                                                                                                                                            | ![Sample Gif](gifs/12.gif) |
| 13    | ```⠁⠂⠄⡀⢀⠠⠐⠈```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/13.gif) |
| 14    | ```⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏```                                                                                                                                                                                                                                                                          | ![Sample Gif](gifs/14.gif) |
| 15    | ```abcdefghijklmnopqrstuvwxyz```                                                                                                                                                                                                                                                          | ![Sample Gif](gifs/15.gif) |
| 16    | ```▉▊▋▌▍▎▏▎▍▌▋▊▉```                                                                                                                                                                                                                                                                       | ![Sample Gif](gifs/16.gif) |
| 17    | ```■□▪▫```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/17.gif) |
| 18    | ```←↑→↓```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/18.gif) |
| 19    | ```╫╪```                                                                                                                                                                                                                                                                                  | ![Sample Gif](gifs/19.gif) |
| 20    | ```⇐⇖⇑⇗⇒⇘⇓⇙```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/20.gif) |
| 21    | ```⠁⠁⠉⠙⠚⠒⠂⠂⠒⠲⠴⠤⠄⠄⠤⠠⠠⠤⠦⠖⠒⠐⠐⠒⠓⠋⠉⠈⠈```                                                                                                                                                                                                                                                       | ![Sample Gif](gifs/21.gif) |
| 22    | ```⠈⠉⠋⠓⠒⠐⠐⠒⠖⠦⠤⠠⠠⠤⠦⠖⠒⠐⠐⠒⠓⠋⠉⠈```                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/22.gif) |
| 23    | ```⠁⠉⠙⠚⠒⠂⠂⠒⠲⠴⠤⠄⠄⠤⠴⠲⠒⠂⠂⠒⠚⠙⠉⠁```                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/23.gif) |
| 24    | ```⠋⠙⠚⠒⠂⠂⠒⠲⠴⠦⠖⠒⠐⠐⠒⠓⠋```                                                                                                                                                                                                                                                                   | ![Sample Gif](gifs/24.gif) |
| 25    | ```ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ```                                                                                                                                                                                                                             | ![Sample Gif](gifs/25.gif) |
| 26    | ```. .. ...```                                                                                                                                                                                                                                                                            | ![Sample Gif](gifs/26.gif) |
| 27    | ```▁▂▃▄▅▆▇█▉▊▋▌▍▎▏▏▎▍▌▋▊▉█▇▆▅▄▃▂▁```                                                                                                                                                                                                                                                      | ![Sample Gif](gifs/27.gif) |
| 28    | ```.oO°Oo.```                                                                                                                                                                                                                                                                             | ![Sample Gif](gifs/28.gif) |
| 29    | ```+x```                                                                                                                                                                                                                                                                                  | ![Sample Gif](gifs/29.gif) |
| 30    | ```v<^>```                                                                                                                                                                                                                                                                                | ![Sample Gif](gifs/30.gif) |
| 31    | ```>>---> >>--->  >>--->   >>--->    >>--->    <---<<    <---<<   <---<<  <---<< <---<<```                                                                                                                                                                                                | ![Sample Gif](gifs/31.gif) |
| 32    | ```\| \|\| \|\|\| \|\|\|\| \|\|\|\|\| \|\|\|\|\|\| \|\|\|\|\| \|\|\|\| \|\|\| \|\| \|```                                                                                                                                                                                                  | ![Sample Gif](gifs/32.gif) |
| 33    | ```[] [=] [==] [===] [====] [=====] [======] [=======] [========] [=========] [==========]```                                                                                                                                                                                             | ![Sample Gif](gifs/33.gif) |
| 34    | ```(*---------) (-*--------) (--*-------) (---*------) (----*-----) (-----*----) (------*---) (-------*--) (--------*-) (---------*)```                                                                                                                                                   | ![Sample Gif](gifs/34.gif) |
| 35    | ```█▒▒▒▒▒▒▒▒▒ ███▒▒▒▒▒▒▒ █████▒▒▒▒▒ ███████▒▒▒ ██████████```                                                                                                                                                                                                                              | ![Sample Gif](gifs/35.gif) |
| 36    | ```[                    ] [=>                  ] [===>                ] [=====>              ] [======>             ] [========>           ] [==========>         ] [============>       ] [==============>     ] [================>   ] [==================> ] [===================>]``` | ![Sample Gif](gifs/36.gif) |
| 37    | ```🕐 🕑 🕒 🕓 🕔 🕕 🕖 🕗 🕘 🕙 🕚 🕛```                                                                                                                                                                                                                                                             | ![Sample Gif](gifs/37.gif) |
| 38    | ```🕐 🕜 🕑 🕝 🕒 🕞 🕓 🕟 🕔 🕠 🕕 🕡 🕖 🕢 🕗 🕣 🕘 🕤 🕙 🕥 🕚 🕦 🕛 🕧```                                                                                                                                                                                                                                     | ![Sample Gif](gifs/38.gif) |
| 39    | ```🌍 🌎 🌏```                                                                                                                                                                                                                                                                               | ![Sample Gif](gifs/39.gif) |
| 40    | ```◜ ◝ ◞ ◟```                                                                                                                                                                                                                                                                             | ![Sample Gif](gifs/40.gif) |
| 41    | ```⬒ ⬔ ⬓ ⬕```                                                                                                                                                                                                                                                                             | ![Sample Gif](gifs/41.gif) |
| 42    | ```⬖ ⬘ ⬗ ⬙```                                                                                                                                                                                                                                                                             | ![Sample Gif](gifs/42.gif) |
| 43    | ```[>>>          >] []>>>>        [] []  >>>>      [] []    >>>>    [] []      >>>>  [] []        >>>>[] [>>          >>]```                                                                                                                                                              | ![Sample Gif](gifs/43.gif) |

## Features

* Start
* Stop
* Restart
* Reverse direction
* Update the spinner character set
* Update the spinner speed
* Prefix or append text
* Change spinner color, background, and text attributes such as bold / italics
* Get spinner status
* Chain, pipe, redirect output
* Output final string on spinner/indicator completion

## Examples

```Go
package main

import (
	"github.com/briandowns/spinner"
	"time"
)

func main() {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)  // Build our new spinner
	s.Start()                                                    // Start the spinner
	time.Sleep(4 * time.Second)                                  // Run for some time to simulate work
	s.Stop()
}
```

## Update the character set and restart the spinner

```Go
s.UpdateCharSet(spinner.CharSets[1])  // Update spinner to use a different character set
s.Restart()                           // Restart the spinner
time.Sleep(4 * time.Second)
s.Stop()
```

## Update spin speed and restart the spinner

```Go
s.UpdateSpeed(200 * time.Millisecond) // Update the speed the spinner spins at
s.Restart()
time.Sleep(4 * time.Second)
s.Stop()
```

## Reverse the direction of the spinner

```Go
s.Reverse() // Reverse the direction the spinner is spinning
s.Restart()
time.Sleep(4 * time.Second)
s.Stop()
```

## Provide your own spinner

(or send me an issue or pull request to add to the project)

```Go
someSet := []string{"+", "-"}
s := spinner.New(someSet, 100*time.Millisecond)
```

## Prefix or append text to the spinner

```Go
s.Prefix = "prefixed text: " // Prefix text before the spinner
s.Suffix = "  :appended text" // Append text after the spinner
```

## Set or change the color of the spinner.  Default color is white. The spinner will need to be restarted to pick up the change.

```Go
s.Color("red") // Set the spinner color to red
```

You can specify both the background and foreground color, as well as additional attributes such as `bold` or `underline`.

```Go
s.Color("red", "bold") // Set the spinner color to a bold red
```

Or to set the background to black, the foreground to a bold red:

```Go
s.Color("bgBlack", "bold", "fgRed")
```

Below is the full color and attribute list:

```
// default colors
red
black
green
yellow
blue
magenta
cyan
white

// attributes
reset
bold
faint
italic
underline
blinkslow
blinkrapid
reversevideo
concealed
crossedout

// foreground text
fgBlack
fgRed
fgGreen
fgYellow
fgBlue
fgMagenta
fgCyan
fgWhite

// foreground Hi-Intensity text
fgHiBlack
fgHiRed
fgHiGreen
fgHiYellow
fgHiBlue
fgHiMagenta
fgHiCyan
fgHiWhite

// background text
bgBlack
bgRed
bgGreen
bgYellow
bgBlue
bgMagenta
bgCyan
bgWhite

// background Hi-Intensity text
bgHiBlack
bgHiRed
bgHiGreen
bgHiYellow
bgHiBlue
bgHiMagenta
bgHiCyan
bgHiWhite
```

## Generate a sequence of numbers

```Go
setOfDigits := spinner.GenerateNumberSequence(25)    // Generate a 25 digit string of numbers
s := spinner.New(setOfDigits, 100*time.Millisecond)
```

## Get spinner status

```Go
fmt.Println(s.Active())
```

## Unix pipe and redirect

Feature suggested and write up by [dekz](https://github.com/dekz)

Setting the Spinner Writer to Stderr helps show progress to the user, with the enhancement to chain, pipe or redirect the output. 

This is the preferred method of setting a Writer at this time.

```go
s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
s.Suffix = " Encrypting data..."
s.Start()
// Encrypt the data into ciphertext
fmt.Println(os.Stdout, ciphertext)
```

```sh
> myprog encrypt "Secret text" > encrypted.txt
⣯ Encrypting data...
```

```sh
> cat encrypted.txt
1243hjkbas23i9ah27sj39jghv237n2oa93hg83
```

## Final String Output

Add additional output when the spinner/indicator has completed. The "final" output string can be multi-lined and will be written to wherever the `io.Writer` has been configured for.

```Go
s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
s.FinalMSG = "Complete!\nNew line!\nAnother one!\n"
s.Start()                 
time.Sleep(4 * time.Second)
s.Stop()                   
```

Output
```sh
Complete!
New line!
Another one!
```
