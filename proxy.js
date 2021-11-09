const proxy = require("node-tcp-proxy");
const util = require("util");
const serviceHosts = ["127.0.0.1"];
const servicePorts = [5432];
const { Buffer } = require('buffer')
const crypto = require('crypto');
const Parser = require ('./parser');
const hexdump = require('hexdump-nodejs');
const Users = require('./users.js');

let clientParser;
let serverParser;

let clientSocket;
let serverSocket;

let matchedUser = undefined;

const { readString, readInt32BE, readUInt32BE, readInt16BE, writeString, writeStrings } = require('./helpers.js');

let users = null;

if ( process.env.USERS_DB ) {
    users = new Users();
    users.load( process.env.USERS_DB );
}

function build(m){

    if ( m === null || m.drop )
        return Buffer.alloc(0);

    let tl = ( m.type !== 0 ? 1 : 0 );
    let ml = m.message.length;

    let buffer = Buffer.alloc( tl + ( ml > 0 ? 4 : 0 ) + ml );

    if ( m.type !== 0 )
        buffer[0] = m.type.charCodeAt(0);

    if ( m.message.length > 0 ) {
        let length = m.message.length + 4;

        buffer.writeInt32BE(length, tl);

        buffer.set(m.message, tl + 4);
    }
    return buffer;
}

function xorBuffers(a, b) {
    if (!Buffer.isBuffer(a)) {
        throw new TypeError('first argument must be a Buffer')
    }
    if (!Buffer.isBuffer(b)) {
        throw new TypeError('second argument must be a Buffer')
    }
    if (a.length !== b.length) {
        throw new Error('Buffer lengths must match')
    }
    if (a.length === 0) {
        throw new Error('Buffers cannot be empty')
    }
    return Buffer.from(a.map((_, i) => a[i] ^ b[i]))
}

function hmacSha256(key, msg) {
    return crypto.createHmac('sha256', key).update(msg).digest();
}

function sha256(text) {
    return crypto.createHash('sha256').update(text).digest();
}

function Hi(password, saltBytes, iterations) {

    let ui1 = hmacSha256(password, Buffer.concat([saltBytes, Buffer.from([0, 0, 0, 1])]))
    let ui = ui1;

    for (var i = 0; i < iterations - 1; i++) {
        ui1 = hmacSha256(password, ui1);
        ui = xorBuffers(ui, ui1)
    }

    return ui
}



authFlows = {};
authFlows['SCRAM-SHA-256'] = function(){

    const clientNonce = crypto.randomBytes(18).toString('base64');

    let client_first_message = null;
    let server_first_message = null;
    let client_final_message = null;
    let server_final_message = null;

    let serverSignatureBytes;

    function readAttrs(d){

        let attrs = {};
        for( let kv of d.split(',') ){
            let k = kv.substr(0,1);
            let v = kv.substr(2 );

            if ( k )
                attrs[k] = v;
        }

        return attrs;
    }


    this.login = (user, password) => {

        // Kick off the login sequence
        let offset = 0;
        let alg = 'SCRAM-SHA-256';

        client_first_message = `n,,n=,r=${clientNonce}`;

        let buf = Buffer.alloc(alg.length + 4 + client_first_message.length + 1 );

        buf.write('SCRAM-SHA-256', offset); offset += alg.length + 1;
        buf.writeUInt32BE(32, offset); offset += 4;
        buf.write(client_first_message, offset);

        let m = {
            type:'p',
            message: buf
        };

        console.log( `Auth Sent : (${m.type})`);
        console.log(hexdump(Buffer.from(m.message)));

        serverSocket.write(build(m));
    };

    this.send_password = (password) => {

       // let attrs = readAttrs(client_final_message);

        let attrsClientFirstMessage = readAttrs(client_first_message);
        let attrsServerFirstMessage = readAttrs(server_first_message);

        let saltBytes = Buffer.from(attrsServerFirstMessage.s, 'base64');

        let saltedPassword = Hi(password, saltBytes, attrsServerFirstMessage.i);

        let clientKey = hmacSha256(saltedPassword, 'Client Key');
        let storedKey = sha256(clientKey);

        let clientFinalMessageWithoutProof = `c=biws,r=${attrsServerFirstMessage.r}`;

        let authMessage = `n=,r=${attrsClientFirstMessage.r},${server_first_message},${clientFinalMessageWithoutProof}`;

        let clientSignature = hmacSha256(storedKey, authMessage);
        let clientProofBytes = xorBuffers(clientKey, clientSignature);
        let clientProof = clientProofBytes.toString('base64');

        let finalAuthMessage = `${clientFinalMessageWithoutProof},p=${clientProof}`;

        let serverKey = hmacSha256(saltedPassword, 'Server Key');
        serverSignatureBytes = hmacSha256(serverKey, authMessage).toString('base64');

        let m = {
            type:'p',
            message: Buffer.from(finalAuthMessage, "utf-8")
        };

        console.log( `Auth Sent : (${m.type})`);
        console.log(hexdump(Buffer.from(m.message)));

        serverSocket.write(build(m));
    };

    this.readClient = (m) => {
        let offset = 0;
        let data = m.parsed.data;

        if ( client_first_message === null ) {
            let alg = readString(data, 0);
            offset += alg.length + 1;

            if (alg === 'SCRAM-SHA-256') {
                let length = readInt32BE(data, offset);
                offset += 4;

                client_first_message = Buffer.from(data.slice(offset, offset + length)).toString('utf-8');

                m.parsed.data = {alg, attrs : readAttrs(client_first_message), raw : client_first_message };
            }
        } else{

            client_final_message = Buffer.from(data).toString('utf-8');

            m.parsed.data = {attrs : attrs, raw : client_final_message };
        }
    };

    this.readServer = (m) => {
        let data = m.parsed.data;

        if ( server_first_message === null ) {

            server_first_message = Buffer.from(data).toString('utf-8');

            m.parsed.data = {attrs : readAttrs(server_first_message), raw : server_first_message};
        } else {

            server_final_message = Buffer.from(data).toString('utf-8');

            m.parsed.data = {attrs : readAttrs(server_final_message), raw : server_final_message};

            if ( serverSignatureBytes !== null ){
                if ( m.parsed.data.attrs.v !== serverSignatureBytes ){
                    debugger;
                }
            }
        }
    }
};

let authProcessor = null;

function processClientMessage(m){
    if ( matchedUser ) {
        if (m.type === 0) {

            let data = readUInt32BE(m.message, 0);

            // SSL Upgrade request
            if (data === 80877103) {
            }

            // Initial Context
            if (data === 196608) {

                console.log(`Initial Context being transformed`);

                let offset = 4;

                let fields = [];
                while (m.message[offset] !== 0) {
                    let field = readString(m.message, offset);
                    offset += field.length + 1;
                    fields.push(field);
                }

                fields[1] = matchedUser.user;
                fields[3] = matchedUser.db;

                let sBuf = writeStrings(fields);

                m.message = Buffer.alloc(4 + sBuf.length);
                m.message.writeUInt32BE(data);
                m.message.set(sBuf, 4);
            }
        }

        if (m.type === 'p') {
            m.drop = true;
            if (authProcessor)
                authProcessor.readClient(m);
        }
    }

    console.log( `Client Sent : (${m.type})`);
    console.log(m.parsed);
    console.log(hexdump(Buffer.from(m.message)));
}

function processServerMessage(m){
    console.log( `Server Responded : (${m.type})`);
    console.log(m.parsed);
    console.log(hexdump( Buffer.from(m.message) ));

    if ( matchedUser ) {
        if (m.type === 'R') {

            //AuthenticationOK
            if (m.parsed.type === 0) {
                authProcessor = null;
            }
            //AuthenticationSASL
            if (m.parsed.type === 10) {
                m.drop = true;
                authProcessor = new authFlows[m.parsed.algorithms[0]]();

                authProcessor.login(matchedUser.user, matchedUser.password);
            }
            // AuthenticationSASLContinue, AuthenticationSASLFinal
            if ((m.parsed.type === 11 || m.parsed.type === 12) && authProcessor) {
                m.drop = true;
                authProcessor.readServer(m);

                if (m.parsed.type === 11) {
                    authProcessor.send_password(matchedUser.password)
                } else {

                }
            }
        }
    }
}

var newProxy = proxy.createProxy(15432, serviceHosts, servicePorts, {
    connect: function(context) {
        matchedUser = undefined;

        clientParser = new Parser();
        serverParser = new Parser();

        clientParser.on('message', (m) => {
            processClientMessage(m)
        });

        serverParser.on('message', (m) => {
            processServerMessage(m);
        });

    },
    upstream: function(context, data) {

        //data = Buffer.concat( [ Buffer.from('spiffe://blahblah\0'),  data] )

        clientSocket = context.proxySocket;

        if (matchedUser === undefined && data[0] !== 0x00 ){
            let id = readString( data, 0 );

            if ( users !== null && id.startsWith('spiffe://') ){
                matchedUser = users.find(id);
                console.log(`parsed spiffe id ${id} from inbound stream`);
                if ( matchedUser ){
                    console.log(`spiffe id ${id} resolved to user => ${matchedUser.user}, database =>${matchedUser.db}`);
                } else {
                    console.log(`spiffe id ${id} does not have a user associated, automatic login is disabled.`);
                }
                data = data.slice(id.length + 1);
            }else{
                matchedUser = null;
            }
        }

        clientParser.append(data);

        let r, m;

        r = Buffer.alloc(0);

        while ( (m = clientParser.parse()) !== null) {
            r = Buffer.concat( [r,  build(m)] );
        }

        return r;
    },
    downstream: function(context, data) {

        serverSocket = context.serviceSocket;

        serverParser.append(data);

        let r, m;

        r = Buffer.alloc(0);

        while ( (m = serverParser.parse()) !== null) {
            r = Buffer.concat( [r,  build(m)] );
        }

        // do something with the data and return modified data
        return r;
    },
    serviceHostSelected: function(proxySocket, i) {
        console.log(util.format("Service host %s:%s selected for client %s:%s.",
            serviceHosts[i],
            servicePorts[i],
            proxySocket.remoteAddress,
            proxySocket.remotePort));
        // use your own strategy to calculate i
        return i;
    }
});
