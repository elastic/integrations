FROM friendsofgo/killgrave:0.4.0
WORKDIR /home

ADD imposters /home/imposters

EXPOSE 3000

ENTRYPOINT ["/go/bin/killgrave", "-host", "0.0.0.0", "-imposters", "/home/imposters"]
