const { Buffer } = require('buffer');

module.exports.readString = function (d, offset){
    let i = d.indexOf(0, offset, 'hex');
    return Buffer.from( d.slice( offset, i ) ).toString('utf-8');
};


function writeString(s){
    let b = Buffer.alloc(s.length + 1, 0);
    b.write(s, 'utf-8');
    return b;
};

module.exports.writeString = writeString;

module.exports.writeStrings = function (values){
    let buffers = [];

    for( var s of values ) {
        buffers.push( writeString(s) );
    }

    buffers.push( Buffer.alloc(1,0) );
    return Buffer.concat( buffers );
};


module.exports.readInt32BE = function (b, offset){

    let v = 0;

    v |= (b[offset+0]<<24)>>>0;
    v |= (b[offset+1]<<16);
    v |= (b[offset+2]<<8);
    v |= b[offset+3];

    return v;
};

module.exports.readUInt32BE = function (b, offset){

    let v = 0;

    v |= (b[offset+0]<<24)>>>0;
    v |= (b[offset+1]<<16);
    v |= (b[offset+2]<<8);
    v |= b[offset+3];

    return v;
};

module.exports.readInt16BE = function (b, offset){

    let v = 0;

    v |= (b[offset+0]<<16);
    v |= b[offset+1];

    return v;
};
