# Git submodule testdata

The examples in this testdata directory test a few common Git URL formats. For a full
list of supported Git URL formats, see:
https://stackoverflow.com/questions/31801271/what-are-the-supported-git-url-formats

For the git plumbing commands involved in the faked remote submodule test setup, see
https://stackoverflow.com/questions/34562333/is-there-a-way-to-git-submodule-add-a-repo-without-cloning-it.

Files here are not valid Git submodule configuration filenames. They are copied in each test case
to `t.TempDir` as `.gitmodules`.
