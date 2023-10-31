
Some hacking tools & some usefull scripts. ( Plus an [oomph file](oomph.md).)


``` bash

# HTTP server

python3 -m http.server

# Interactive shell \w python

python -c 'import pty;pty.spawn("/bin/bash")'

# Scan SUID binaries

find / -perm +6000 2>/dev/null | grep '/bin/'                 # It finds binaries at ex /usr/local/bin/ too
find / -perm /6000 2>/dev/null | grep '/bin/' 

```
