# BOFs

A collection of utilities for Cobalt Strike's Beacon Object Files to make our life easier.

| Name | Description | Usage |
|------|-------------|-------|
`send_shellcode_via_pipe` | A BOF that allows the operator to send a shellcode or any byte content via a named pipe. | `send_shellcode_via_pipe <pipe> <file> `|
`cat` | As the name implies, finally allows you to get the content of a text file from Cobalt Strike. Supports remote shares. | `cat <file>`


A particular thanks to [@ajpc500](https://twitter.com/ajpc500) for inspiration ~~and from which I might or might not borrowed some code.~~