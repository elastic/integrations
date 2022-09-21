db = db.getSiblingDB('admin');
db.createUser(
    {
        user: "beats",
        pwd: "pass",
        roles: ["clusterMonitor"]
    }
);