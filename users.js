const fs = require('fs');

function Users(){

    let db = {};

    this.load = (f) => {
        let rawdata = fs.readFileSync(f);
        db = JSON.parse(rawdata);
    };

    this.find = (id) => {
        return db[id] || null
    }

}

module.exports = Users;
