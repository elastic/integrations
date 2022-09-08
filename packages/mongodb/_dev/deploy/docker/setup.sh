sleep 30 | echo Sleeping1 
mongo mongodb://localhost:27017 init.js
sleep 30 | echo Sleeping2
mongo mongodb://localhost:27017 adduser.js
