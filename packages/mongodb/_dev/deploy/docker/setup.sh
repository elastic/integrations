sleep 30 | echo Sleeping
mongo mongodb://localhost:27017 init.js
sleep 30 | echo Sleeping
mongo mongodb://localhost:27017 adduser.js