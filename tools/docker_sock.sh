ssh -vL localhost:2018:localhost:2018 hetax.srv \
  docker run --rm \
  -p 2018:2018 \
  -v /var/run/docker.sock:/docker.sock \
  alpine/socat -dd TCP-LISTEN:2018,fork UNIX-CONNECT:/docker.sock
