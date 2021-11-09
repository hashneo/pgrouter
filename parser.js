'use strict';

const { Buffer } = require('buffer');
const EventEmitter = require('events').EventEmitter;

const { readString, readInt32BE, readUInt32BE, readInt16BE } = require('./helpers.js');

let processors = {};

processors['p'] = function(d) {

    let result = {};

    let offset = 0;
    result.data = d.slice( offset ) ;

    return result;
};

processors['R'] = function(d){

    let result = {};

    let offset = 0;
    let type = readInt32BE(d, offset); offset += 4;

    result.type = type;
    //AuthenticationSASL
    if (type === 10){
        result.algorithms = [];
        do {
            let alg = readString(d, offset); offset += alg.length + 1;
            result.algorithms.push(alg);
        } while ( d[offset] !== 0 )
    }

    //AuthenticationSASLContinue
    if (type === 11){
        result.data = d.slice( offset ) ;
    }

    //AuthenticationSASLFinal
    if (type === 12){
        result.data = d.slice( offset ) ;
    }

    return result;
};

processors['T'] = function(d){
    let result = { fields : [] };
    let offset = 0;
    let fields = readInt16BE(d, offset); offset += 2;
    for ( let i = 0 ; i <  fields ; i++ ){
        let name = readString(d, offset); offset += name.length + 1;
        let table_id  = readInt32BE(d, offset); offset += 4;
        let column_id = readInt16BE(d, offset); offset += 2;
        let type_id   = readInt32BE(d, offset); offset += 4;
        let type_size = readInt16BE(d, offset); offset += 2;
        let type_mod  = readInt32BE(d, offset); offset += 4;
        let fmt_code  = readInt16BE(d, offset); offset += 2;

        result.fields.push({
                name,
                table_id,
                column_id,
                type_id,
                type_size,
                type_mod,
                fmt_code
            }
        )
    }
    return result;
};


function app(){

    this.buffer = [];
    this.message = [];

    this.type = 0;
    this.length = 0;

    EventEmitter.call(this);

    const that = this;

    this.append = (data) => {
        that.buffer.push( ...data );
    };

    this.parse = () => {

        let offset=0;

        if ( that.buffer.length === 0 )
            return null;

        // Read the Header info
        if ( that.length === 0 ) {
            that.type = 0;

            // Read Type
            if (that.buffer[0] !== 0 ) {
                that.type = String.fromCharCode(that.buffer[offset++]);
            }

            // Read Length
            if (that.buffer.length > 1) {
                that.length = readUInt32BE( that.buffer, offset );
                offset += 4;
                that.length -= 4;
            }

            // We have 2 types here, SSL upgrade request and Initial Connection
            if ( that.type === 0 ){
                /*
                let data = readUInt32BE( buffer, offset );

                if ( data === 80877103 ){
                    // SSL upgrade request
                    type = 80877103
                }

                if ( data === 196608 ){
                    // Initial Login Data
                    type = 196608
                }
                */
            }

            // Remove the header from the buffer
            that.buffer = that.buffer.slice(offset);
        }

        if (that.length > 0 || that.type !== 0){

            let needed = that.length - that.message.length;

            if ( needed > 0 ) {
                let block = that.buffer.slice(0, Math.min( needed, that.buffer.length ) );
                that.message = that.message.concat( block );
                that.buffer = that.buffer.slice(needed);
            }

            if ( that.message.length === that.length ){

                let parsed = {};

                if ( processors[that.type] !== undefined ){
                    parsed = processors[that.type](that.message);
                }

                let d = {
                    type: that.type,
                    message: that.message,
                    parsed: parsed
                };

                that.emit('message', d);

                that.message = [];
                that.length = 0;
                that.type = 0;

                return d;
            }
        }

        return null;
    }
}

app.prototype = Object.create(EventEmitter.prototype);

module.exports = app;
