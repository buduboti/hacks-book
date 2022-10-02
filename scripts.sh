
# Interactive shell \w python

python -c 'import pty;pty.spawn("/bin/bash")'

# Scan SUID binaries

find / -perm +6000 2>/dev/null | grep '/bin/'                         # It finds binaries at ex /usr/local/bin/ too
