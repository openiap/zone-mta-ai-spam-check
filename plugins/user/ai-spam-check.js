'use strict';
const { PassThrough } = require('stream');
const { MongoClient, Db, Double } = require('mongodb');
const GridFSBucket = require('mongodb').GridFSBucket;
// const { Transform } = require('stream');
const { OpenAI } = require('openai');
const { openiap } = require("@openiap/nodeapi")
const mailsplit = require('mailsplit');
const fs = require('fs');
const os = require('os');
let fake_scan = false;
let reject_spam = false;
let drop_outgoing = false;
let enable_validator = false;

let auto_deny_firsttime_spammers = false;
let auto_trust_firsttime_notspam = false;

let needed_confidence = 0.7;
let validator_email = 'domain-validator@cloud.openiap.io';
if (os.hostname().indexOf("nix") > -1) {
    validator_email = 'domain-validator@home.openiap.io';
    fake_scan = false;
    reject_spam = true;
    drop_outgoing = false;
    enable_validator = false;
    auto_deny_firsttime_spammers = false;
    auto_trust_firsttime_notspam = false;
}
/*
knowntype: relay, trusted, drop, spam, disposable, validating, validated, approved

relay: "the customer"
trusted: allow, do not scan
drop: silently drop, keep copy in db
spam: reject mails
disposable: reject mails

First time getting an email from a new domain;
    - Scan for spam:
        - spam: reject, and mark domain as spam. All emails will be rejected
        - not spam: allow, and mark domain as approved. All emails will be allowed, but still scanned for spam
        
        - not enough data: send email to user to validate domain
            - while validating, keep emails in db
            - if user replyed to email, mark domain as validated, and allow emails, but scan for spam

validating: validation email sent, waiting for reply. Store in db
validated: user replyed to validation email

approved: spam check on first email, did not detect spam, so allowed. Future emails will be scanned


https://www.talosintelligence.com/reputation_center/lookup?search=35.205.203.52
https://answers.microsoft.com/en-us/outlook_com/forum/all/since-part-of-their-network-is-on-our-block-list/d956ad0e-3019-4440-bbb1-15693d66e438

_dmarc
Monitor Only:
v=DMARC1; p=none; rua=mailto:info@openiap.io;
Quarantine Failing Emails:
v=DMARC1; p=quarantine; rua=mailto:info@openiap.io; pct=100;
Reject Failing Emails:
v=DMARC1; p=reject; rua=mailto:info@openiap.io;

*/


const PluginInstance = require('zone-mta/lib/plugin-handler.js');
const { env } = require('process');
const MailQueue = require('zone-mta/lib/mail-queue.js');
/**
 * 
 * @param {PluginInstance} app 
 * @param {any} done 
 * @returns 
 */
function init(app, done) {
    if (fs.existsSync('config/.env')) {
        app.logger.info('ai-spam-check', 'loading env from config/.env');
        require("dotenv").config({ path: 'config/.env' });
    }
    const client = new openiap();
    const SMTPclient = require("nodemailer").createTransport({
        host: "127.0.0.1",
        port: (os.hostname().indexOf("nix") > -1) ? 25 : 2525
    });

    if (app.config == null || app.config.enabled != true) return;
    client.connect().catch((err) => {
        app.logger.error('ai-spam-check', err.message);
        console.log(err);
    }).then(async () => {
        try {
            await client.CreateCollection({ collectionname: "mailevents", timeseries: { timeField: "_created", metaField: "metadata" } })
            app.logger.info('ai-spam-check', 'created mailevents timeseries collection');
        } catch (error) {
            // console.error(error);
        }
    });

    const apiKey = process.env['OPENAI_API_KEY'] || app.config.OPENAI_API_KEY;
    const openai = new OpenAI({ apiKey });
    const secret_key = process.env['SECRET_KEY'] || app.config.SECRET_KEY || "supersecret";

    const config = require('wild-config');
    var q = new MailQueue(config.queue);
    q.init((err) => {
        if (err != null) {
            app.logger.error('ai-spam-check', err.message);
        }
    });


    /** @type {MongoClient} */
    var db = app.db;
    /** @type {Db} */
    var mongodb = app.mongodb;
    const randomseconds = Math.floor(Math.random() * 30);

    const housekeeping = async () => {
        try {
            if (enable_validator == true) {
                const domains = await mongodb.collection('zone-queue').distinct('domain', { sendingZone: "validating" });
                for (let i = 0; i < domains.length; i++) {
                    let known = await client.FindOne({ collectionname: "maildomains", query: { "$or": [{ domains: domains[i] }, { name: domains[i] }] } });
                    if (known == null || known._type != "validating") {
                        await mongodb.collection('zone-queue').updateMany({ domain: domains[i], sendingZone: "validating" }, { $set: { sendingZone: 'default' } });
                        app.logger.info('ai-spam-check', `Domain ${domains[i]} is now longer validating, so updating sendingZone to 'default'`);
                    }
                }
            }
            let messages = await mongodb.collection('zone-queue').find({ sendingZone: "delete" }).toArray();
            for (let i = 0; i < messages.length; i++) {
                const message = messages[i];
                app.logger.info('ai-spam-check', `Removing message ${message.id} ${message.seq} from queue`);
                q.remove(message.id, message.seq, err => {
                    if (err != null) {
                        app.logger.error('ai-spam-check', "DEL cleanup " + err.message);
                    }
                });
            }
            var or = [{ _acl: { "$exists": false } }, { subject: { "$exists": false } }]
            messages = await mongodb.collection('zone-queue').find({ sendingZone: { "$in": ["quarantine", "archive"] }, "$or": or }).toArray();
            for (let i = 0; i < messages.length; i++) {
                const message = messages[i];
                try {
                    if (message._acl == null) {
                        // const promptsquery = {_type: 'promt', "$or": [{domain: {"$in": [message.domain]}}, {email: {"$in": [message.recipient]}}]};
                        // const prompts = await client.Query({ collectionname: "mailprompts", query: promptsquery });
                        const config = await LookupConfigDomain(client, null, message.recipient);
                        if (config == null) {
                            app.logger.info('ai-spam-check', `No prompts found for ${message.recipient}`);
                            continue;
                        }
                        app.logger.info('ai-spam-check', `Update message ${message.id} ${message.seq} with _acl from email prompt ${config.name}`);
                        await mongodb.collection('zone-queue').updateOne({ _id: message._id }, { $set: { _acl: config._acl } });
                    }
                    if (message.subject == null) {
                        q.getInfo(message.id, async (err, info) => {
                            let headers = new mailsplit.Headers(info.meta.headers || []);
                            message.subject = headers.getFirst('subject');
                            message.from = info.meta.from;
                            app.logger.info('ai-spam-check', `Update message ${message.id} ${message.seq} with subject and from`);
                            await mongodb.collection('zone-queue').updateOne({ _id: message._id }, { $set: { subject: message.subject, from: message.from } });
                        });
                    }
                } catch (error) {
                    app.logger.error('ai-spam-check', error.message);
                }

            }
            messages = await mongodb.collection('mail.files').find({ "metadata._acl": { "$exists": false } }).toArray();
            for (let i = 0; i < messages.length; i++) {
                const message = messages[i];
                try {
                    if (message.metadata?.data?.id == null) continue;
                    q.getInfo(message.metadata?.data?.id, async (err, info) => {
                        if (err != null) {
                            app.logger.error('ai-spam-check', err.message);
                            return;
                        }
                        if (info == null || info.messages == null) {
                            // app.logger.error('ai-spam-check', `No info found for ${message.metadata.recipient}`);
                            return;
                        }
                        var _acl = [];
                        for (let n = 0; n < info.messages.length; n++) {
                            const msg = info.messages[n];
                            const config = await LookupConfigDomain(client, null, msg.recipient);
                            if (config == null) {
                                app.logger.info('ai-spam-check', `No prompts found for ${msg.recipient}`);
                                continue;
                            }
                            for (let y = 0; y < config._acl.length; y++) {
                                let exists = _acl.find((x) => x._id == config._acl[y]._id);
                                if (exists == null) {
                                    _acl.push(config._acl[y]);
                                } else if (exists.rights < config._acl[y].rights) {
                                    exists.rights = config._acl[y].rights;
                                }
                            }

                        }
                        if (_acl.length > 0) {
                            app.logger.info('ai-spam-check', `Update message ${message.metadata.data.id} with _acl from email prompt(s)`);
                            await mongodb.collection('mail.files').updateOne({ _id: message._id }, { $set: { "metadata._acl": _acl } });
                        }
                    });

                    // if(message.metadata?.data?.from != null) {
                    //     const from = message.metadata.data.from;
                    //     const domain = from.split('@')[1];
                    //     const promptsquery = {_type: 'promt', "$or": [{domain: {"$in": [domain]}}, {email: {"$in": [from]}}]};
                    //     const prompts = await client.Query({ collectionname: "mailprompts", query: promptsquery });
                    //     if(prompts.length == 0) {
                    //         app.logger.info('ai-spam-check', `No prompts found for ${message.metadata.recipient}`);
                    //         continue;
                    //     }
                    //     const byemail = prompts.find((x) => x.email != null && x.email.indexOf(from) != -1);
                    //     const bydomain = prompts.find((x) => x.domain != null && x.domain.indexOf(domain) != -1);
                    //     if(byemail != null) {
                    //         app.logger.info('ai-spam-check', `Update message ${message.id} with _acl from email prompt ${byemail.name}`);
                    //         await mongodb.collection('mail.files').updateOne({ _id: message._id }, { $set: { "metadata._acl": byemail._acl } });
                    //     } else if(bydomain != null) {
                    //         app.logger.info('ai-spam-check', `Update message ${message.id} with _acl from email prompt ${bydomain.name}`);
                    //         await mongodb.collection('mail.files').updateOne({ _id: message._id }, { $set: { "metadata._acl": bydomain._acl } });
                    //     }
                    // }
                } catch (error) {
                    app.logger.error('ai-spam-check', error.message);
                }
            }

        } catch (error) {
        }
        setTimeout(housekeeping, 1000 * randomseconds);
    };
    setTimeout(housekeeping, 1000 * randomseconds);

    app.addHook('sender:fetch', async (delivery) => {
        if (drop_outgoing) {
            let err = new Error('Puf, and the mail is gone');
            err.responseCode = 554;
            delivery.skipBounce = err.message;
            app.logger.info('ai-spam-check', `id=${delivery.id} ${err.responseCode} ${err.message}`);
            await AddMailEvent(client, delivery, null, "rejected");
            throw err
        }
    });
    app.addHook('sender:connected', async (delivery, info) => {
        // await AddMailEvent(client, delivery, info, "delivered");
        var b = true;
    });    
    app.addHook('sender:delivered', async (delivery, info) => {
        await AddMailEvent(client, delivery, info, "delivered");
    });
    app.addHook('sender:tlserror', async (delivery, info, err) => {
        console.log(err)
        await AddMailEvent(client, delivery, info, "tlserror", null, err);
    });
    app.addHook('sender:responseError', async (delivery, info, err) => {        
        console.log(err)
        await AddMailEvent(client, delivery, info, "faileddelivery", null, err);
    });
    app.addHook('queue:route', async (envelope, routing) => {
        app.logger.info('ai-spam-check', `id=${envelope.sessionId} interface=${envelope.interface} deliveryZone=${routing.deliveryZone} ${envelope.from?.toLowerCase()} -> ${envelope.to}`);
        if (envelope.from.toLowerCase() == validator_email) { // allow outgoing validator email
            await AddMailEvent(client, envelope, routing, "route");
            return;
        }
        if (envelope.to && envelope.to.length > 0) { // disallow incomming validator email ( non existential email )
            for (let i = 0; i < envelope.to.length; i++) {
                if (envelope.to[i].toLowerCase() == validator_email) {
                    if (routing.deliveryZone != "drop") {
                        app.logger.info('ai-spam-check', `id=${envelope.sessionId} deliveryZone updated from '${routing.deliveryZone}' to 'drop'`);
                        routing.deliveryZone = "drop";
                    }
                }
            }
        }

        const to = routing.recipient;
        if (envelope.quarantinelist != null && envelope.quarantinelist.indexOf(to) != -1) {
            app.logger.info('ai-spam-check', `id=${envelope.sessionId} deliveryZone updated from '${routing.deliveryZone}' to 'quarantine'`);
            routing.deliveryZone = "quarantine";
            await AddMailEvent(client, envelope, routing, "quarantine");
            return;
        } else if (envelope.droplist != null && envelope.droplist.indexOf(to) != -1) {
            app.logger.info('ai-spam-check', `id=${envelope.sessionId} deliveryZone updated from '${routing.deliveryZone}' to 'delete'`);
            routing.deliveryZone = "delete";
            await AddMailEvent(client, envelope, routing, "delete");
            return;
        }
        const allowrelay = await allowRelay(to);
        if (allowrelay == false) {
            app.logger.info('ai-spam-check', `id=${envelope.sessionId} deliveryZone updated from '${routing.deliveryZone}' to 'delete'`);
            routing.deliveryZone = "delete";
            await AddMailEvent(client, envelope, routing, "delete");
            return;
        }
        await AddMailEvent(client, envelope, routing, "route");
    });
    app.addHook('message:queue', async (envelope, messageInfo) => {
        await setLocalMeta(envelope.id, envelope);
        if (reject_spam == true && envelope.to != null) {
            if (envelope.whitelist != null && envelope.whitelist.length > 0) {
            } else if (envelope.quarantinelist != null && envelope.quarantinelist.length > 0) {
            } else {
                if (!Array.isArray(envelope.to)) envelope.to = [envelope.to];
                const emails = envelope.to.map((x) => x.toLowerCase());
                if (envelope.droplist != null && envelope.droplist.length > 0) {
                    var filtered = emails.filter((x) => envelope.droplist.indexOf(x) == -1);
                    if (filtered.length == 0) {
                        let err = new Error("Mail rejected: Spam detected"); // include reason in error message ? I don't think so.
                        err.responseCode = 550;
                        app.logger.info('ai-spam-check', `id=${envelope.sessionId} ${err.responseCode} ${err.message}`);
                        await AddMailEvent(client, envelope, messageInfo, "rejected");
                        throw app.reject(envelope, 'ai-spam-check', messageInfo, `${err.responseCode} ${err.message}`);
                    }
                }

            }
        }
        await AddMailEvent(client, envelope, messageInfo, "accepted");
        // const domain = envelope.from.split('@')[1];
        // const knowntype = await LookupDomain(client, envelope, domain);
        // const result = envelope.aireport;
        // if (result == null) {
        //     return; // was not scanned (must be trusted?)
        // }
        // if (knowntype == "unknown") {
        //     // if spam, reject and add to db as spam
        //     // if unsure, add to db as aproved and allow, or send validation email, and store in db
        //     // if not spam, add to db as aproved and allow
        //     if (result.spam == true && result.confidence >= needed_confidence) {
        //         if (knowntype == "unknown") {
        //             if(auto_deny_firsttime_spammers == true) {
        //                 await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name", item: { "_ai": result, name: domain, _type: "spam", messageid: messageInfo.messageId } });
        //             }
        //         }
        //         // envelope.knowntype = "spam";
        //         // let err = new Error("Mail rejected: " + result.reason);
        //         // err.responseCode = 550;
        //         // app.logger.info('ai-spam-check', `[${envelope.sessionId}][${err.responseCode}] ${err.message}`);
        //         // throw app.reject(envelope, 'ai-spam-check', messageInfo, `${err.responseCode} ${err.message}`);
        //     } else if (result.confidence < needed_confidence) {
        //         if (enable_validator == false) {
        //             // let err = new Error("Mail rejected: " + result.reason);
        //             // err.responseCode = 550;
        //             // app.logger.info('ai-spam-check', `[${envelope.sessionId}][${err.responseCode}] ${err.message}`);
        //             // throw app.reject(envelope, 'ai-spam-check', messageInfo, `${err.responseCode} ${err.message}`);
        //             envelope.knowntype = "approved";
        //             return;
        //         }
        //         const info = await SMTPclient.sendMail({
        //             from: validator_email,
        //             to: envelope.from,
        //             subject: 'Domain Validation Required',
        //             text: `Hello user behind ${messageInfo.from}, \nPlease validate your domain, ${domain} is not used for spam, by simply replying to this email.\nThis is to ensure a real human is behind the email address.\n\nThank you.`
        //         });
        //         app.logger.info('ai-spam-check', `[${envelope.sessionId}][SENT] Validation email sent as ${info.messageId}`);
        //         await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name", item: { "_ai": result, name: domain, _type: "validating", messageid: info.messageId } });
        //         envelope.knowntype = "validating";
        //     } else {
        //         envelope.knowntype = "approved";
        //     }
        //     if(envelope.knowntype = "spam" || envelope.knowntype == "validating") {
        //         app.logger.info('ai-spam-check', `[${envelope.sessionId}][DELIVERED] This is spam, ${result.reason}`);
        //     } else {
        //         app.logger.info('ai-spam-check', `[${envelope.sessionId}][DELIVERED] This is not spam, ${result.reason}`);
        //     }
        // } else {
        //     if (result.spam == true && result.confidence >= needed_confidence) {
        //         envelope.knowntype = "spam";
        //         app.logger.info('ai-spam-check', `[${envelope.sessionId}][DELIVERED] This is spam, ${result.reason}`);
        //     } else {
        //         app.logger.info('ai-spam-check', `[${envelope.sessionId}][DELIVERED] This is not spam, ${result.reason}`);
        //     }
        // }
    });
    const allowRelay = async (to) => {
        if (to == validator_email) {
            return true;
        }
        const domain = to.split('@')[1];
        const config = await LookupConfigDomain(client, domain, to);
        if (config == null) {
            return false;
        }
        return true;
    }
    app.addHook('smtp:rcpt_to', (address, session) => {
        return new Promise(async (resolve, reject) => {
            const envelope = session;
            const domain = address.address.split('@')[1];
            app.logger.info('ai-spam-check', `id=${session.id} to=${address.address}`);
            if (address.address == validator_email || envelope.envelope?.mailFrom?.address == validator_email) {
                return resolve();
            } else if (address.address.indexOf("@") == -1) {
                let err = new Error("To must be a valid email address");
                err.responseCode = 550;
                app.logger.info('ai-spam-check', `id=${session.id} ${err.responseCode} ${err.message}`);
                return reject(err);
            } else if (address.address.indexOf("@cloud.openiap.io") > -1) { // test hack, change to openiap.io
                address.address = address.address.replace("@cloud.openiap.io", "@openiap.io");
                return resolve();
            } else if (address.address.indexOf("@home.openiap.io") > -1) { // test hack, change to openiap.io
                address.address = address.address.replace("@home.openiap.io", "@openiap.io");
                return resolve();
            }
            delete envelope.knowntype;
            if ((await allowRelay(address.address)) == false) {
                let err = new Error(`Relaying for ${address.address} denied.`);
                err.responseCode = 550;
                app.logger.info('ai-spam-check', `id=${envelope.sessionId} ${err.responseCode} ${err.message}`);
                await AddMailEvent(client, envelope.envelope, session, "relaydenied");
                return reject(err);
            }
            resolve()

        });
    });
    app.addHook('message:headers', (envelope, messageInfo) => {
        return new Promise(async (resolve, reject) => {
            if (envelope.from == null || envelope.from == "") {
                return resolve();
            }
            if (envelope.to == null) {
                return resolve();
            }
            if (!Array.isArray(envelope.to)) envelope.to = [envelope.to];
            const emails = envelope.to.map((x) => x.toLowerCase());
            if (emails.indexOf(validator_email) != -1) {
                const domain = envelope.from.toLowerCase().split('@')[1];
                if (envelope.headers != null && envelope.headers.lines != null) {
                    const known2 = await client.FindOne({ collectionname: "maildomains", query: { name: domain } });
                    var references = envelope.headers.lines.find((line) => line.key == "references");
                    var inreplyto = envelope.headers.lines.find((line) => line.key == "inreplyto");
                    if (references != null) {
                        if (references.line.indexOf(known2.messageid) > -1) {
                            try {
                                await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name", item: { name: domain, _type: "validated" } });
                            } catch (error) {
                                throw error;
                            }
                            envelope.skipBounce = "Silently drop validationemail that contained " + known2.messageid;
                            envelope.knowntype = "validated"
                        }
                    }
                    if (inreplyto != null) {
                        if (inreplyto.line.indexOf(known2.messageid) > -1) {
                            try {
                                await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name", item: { name: domain, _type: "validated" } });
                            } catch (error) {
                                throw error;
                            }
                            envelope.skipBounce = "Silently drop validationemail that contained " + known2.messageid;
                            envelope.knowntype = "validated"
                        }
                    }
                }
            }
            resolve();
        });
    });
    async function generateId() {
        return new Promise((resolve, reject) => {
            app.getQueue().generateId((err, id) => {
                if (err) {
                    return reject(err);
                }
                resolve(id);
            });
        });
    }
    async function push(id, envelope) {
        return new Promise((resolve, reject) => {
            app.getQueue().push(id, envelope, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });
    }
    async function store(id, stream) {
        return new Promise((resolve, reject) => {
            const q = app.getQueue();
            q.store(id, stream, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });

    }
    async function retrieve(id) {
        return new Promise((resolve, reject) => {
            const q = app.getQueue();
            const stream = q.retrieve(id);
            if (stream == null) {
                return reject(new Error('Stream not found'));
            }
            resolve(stream);
        });
    }
    async function retrieveMessage(id) {
        var stream = await retrieve(id);
        return new Promise((resolve, reject) => {
            var data = '';
            stream.on('data', (chunk) => {
                data += chunk;
            });
            stream.on('end', () => {
                resolve(data);
            });
            stream.on('error', (err) => {
                reject(err);
            });
        }
        );
    }
    async function removeMessage(id) {
        return new Promise((resolve, reject) => {
            const q = app.getQueue();
            q.removeMessage(id, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });
    }

    /**
     * Set metadata for a message
     *
     * @param {String} id The ID of the stored data
     * @param {Object} data Data to store as metadata for the stream
     * @param {Function} callback
     */
    async function setLocalMeta(id, data) {
        return new Promise((resolve, reject) => {
            app.mongodb.collection('archive.files').updateOne(
                {
                    filename: 'message ' + id
                },
                {
                    $set: {
                        'metadata.data': data
                    }
                },
                err => {
                    if (err) {
                        return reject(err);
                    }
                    return resolve();
                }
            );
        });
    }
    async function localstore(id, stream, metadata) {
        return new Promise((resolve, reject) => {
            const gridstore = new GridFSBucket(app.mongodb, {
                bucketName: "archive"
            });
            const store = gridstore.openUploadStream('message ' + id, {
                contentType: 'message/rfc822',
                metadata: {
                    _acl: [{
                        "rights": 65535,
                        "_id": "5a1702fa245d9013697656fb",
                        "name": "admins"
                    }],
                    created: new Date(),
                    data: metadata
                }
            });
            let returned = false;

            stream.once('error', err => {
                if (returned) {
                    return;
                }
                returned = true;

                store.once('finish', () => {
                    reject(err);
                });

                store.end();
            });

            store.once('error', err => {
                if (returned) {
                    return;
                }
                returned = true;
                reject(err);
            });

            store.on('finish', () => {
                if (returned) {
                    return;
                }
                returned = true;

                resolve();
            });

            stream.pipe(store);
        });

    }

    app.addAnalyzerHook(async (envelope, source, destination) => {
        const sourceDuplicate = new PassThrough();
        const sourceForArchive = new PassThrough();

        source.on('data', (chunk) => {
            sourceDuplicate.write(chunk);
            sourceForArchive.write(chunk);
        });

        source.on('end', () => {
            sourceDuplicate.end();
            sourceForArchive.end();
        });

        source.on('error', (error) => {
            sourceDuplicate.emit('error', error);
            sourceForArchive.emit('error', error);
        });
        const meta = JSON.parse(JSON.stringify(envelope))

        await localstore(envelope.id, sourceForArchive, meta);

        sourceDuplicate.pipe(destination).on('error', (err) => {
            app.logger.error('ai-spam-check', 'Error scanning email: %s', err.message);
        });
    });
    app.addAnalyzerHook(async (envelope, source, destination) => {
        if (envelope.from.toLowerCase() == validator_email) {
            app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan of validator email`);
            envelope.knowntype = "trusted";
            return source.pipe(destination);
        }
        if (envelope.to == null) { // NDR's seem to have no to ?
            return source.pipe(destination);
        } else if (!Array.isArray(envelope.to)) {
            envelope.to = [envelope.to];
        }
        if (envelope.to.length > 0) {
            for (let i = 0; i < envelope.to.length; i++) {
                if (envelope.to[i].toLowerCase() == validator_email) {
                    app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan of validator email`);
                    envelope.knowntype = "trusted";
                    return source.pipe(destination);
                }
            }
        }

        const sourceDuplicate = new PassThrough();
        const sourceForParsing = new PassThrough();

        source.on('data', (chunk) => {
            sourceDuplicate.write(chunk);
            sourceForParsing.write(chunk);
        });

        source.on('end', () => {
            sourceDuplicate.end();
            sourceForParsing.end();
        });

        source.on('error', (error) => {
            sourceDuplicate.emit('error', error);
            sourceForParsing.emit('error', error);
        });


        const mail = await require('mailparser').simpleParser(sourceForParsing);

        const emails = envelope.to.map((x) => x.toLowerCase());
        const domains = emails.map((x) => x.split('@')[1]);
        const promptsquery = { _type: 'config', "$or": [{ domains: { "$in": domains } }, { emails: { "$in": emails } }] };

        const prompts = await client.Query({ collectionname: "mailconfig", query: promptsquery });


        let from = envelope.from;
        if(mail.from != null && mail.from.value != null && mail.from.value.length > 0 && mail.from.value[0].address != null && mail.from.value[0].address != "") {
            from = mail.from.value[0].address;
        }

        const domain = from.toLowerCase().split('@')[1];


        if (prompts.length == 0) { // not covered by prompt
            app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan of validator email`);
            return source.pipe(destination);
        }

        const domaintypes = await client.Query({ collectionname: "maildomains", query: { "$or": [{ domain: domain }, { email: from.toLowerCase() }], "config": { "$in": prompts.map(x => x._id) } } });

        let quarantinelist = [];
        let whitelist = [];
        let droplist = [];
        const removeFromList = (list, item) => {
            const index = list.indexOf(item);
            if (index > -1) {
                list.splice(index, 1); // Remove the item in-place
            }
        };

        const addToList = (list, emails, override) => {
            if (emails.length == 0) return;
            var b = true;
            emails.forEach(item => {
                if (override) {
                    removeFromList(quarantinelist, item);
                    removeFromList(whitelist, item);
                    removeFromList(droplist, item);
                }
                var b = true;
                if (!quarantinelist.includes(item) && !whitelist.includes(item) && !droplist.includes(item)) {
                    var b = true;
                    list.push(item);
                }
            });
            var b = true;
        }

        const doScan = async (forexactmatch) => {
            for (let i = 0; i < prompts.length; i++) {
                const prompt = prompts[i];
                const promptdomains = (Array.isArray(prompt.domains) ? prompt.domains : [prompt.domains]).filter((x) => x != null);
                const promptemails = (Array.isArray(prompt.emails) ? prompt.emails : [prompt.emails]).filter((x) => x != null);
                let exactmatch = false;
                if (promptemails.length > 0) {
                    const found = promptemails.find((x) => emails.indexOf(x) != -1);
                    if (found != null) exactmatch = true;
                }
                if (forexactmatch != exactmatch) continue;

                const domaintype = domaintypes.find((x) => x.config == prompt._id);
                if (domaintype != null) {
                    if (domaintype._type == "spam") {
                        if (prompt.quarantine == true) {
                            let _quarantinelist = emails.filter((x) => promptemails.indexOf(x) != -1);
                            addToList(quarantinelist, _quarantinelist, exactmatch);
                            _quarantinelist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                            addToList(quarantinelist, _quarantinelist, exactmatch);
                        } else {
                            let _droplist = emails.filter((x) => promptemails.indexOf(x) != -1);
                            addToList(droplist, _droplist, exactmatch);
                            _droplist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                            addToList(droplist, _droplist, exactmatch);
                        }
                        app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan, domain already marked as spammer for this prompt`);
                        continue;
                    } else if (domaintype._type == "trusted") {
                        let _whitelist = emails.filter((x) => promptemails.indexOf(x) != -1);
                        addToList(whitelist, _whitelist, exactmatch);
                        _whitelist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                        addToList(whitelist, _whitelist, exactmatch);
                        app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan, domain marked as trusted for this prompt`);
                        continue;
                    } else { // TODO: Narrow down, once logic has been moved !!!!
                        let _whitelist = emails.filter((x) => promptemails.indexOf(x) != -1);
                        addToList(whitelist, _whitelist, exactmatch);
                        _whitelist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                        addToList(whitelist, _whitelist, exactmatch);
                    }
                }

                app.logger.info('ai-spam-check', `id=${envelope.id} Analyzing email using ${prompt.name} prompt`);
                const result = await TestMailBody(client, openai, app.config.model, mail, prompt.prompt);
                app.logger.info('ai-spam-check', `id=${envelope.id} ` + (result.spam ? 'Spam' : 'Not spam') + ` with confidence ${result.confidence}`);
                if (result.spam == true && result.confidence >= needed_confidence) {
                    if (prompt.quarantine == true) {
                        let _quarantinelist = emails.filter((x) => promptemails.indexOf(x) != -1);
                        addToList(quarantinelist, _quarantinelist, exactmatch);
                        _quarantinelist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                        addToList(quarantinelist, _quarantinelist, exactmatch);
                    } else {
                        let _droplist = emails.filter((x) => promptemails.indexOf(x) != -1);
                        addToList(droplist, _droplist, exactmatch);
                        _droplist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                        addToList(droplist, _droplist, exactmatch);
                    }
                    await AddMailEvent(client, envelope, null, "scan", result);

                    if (domaintype == null) { // knowntype == "unknown") {
                        if (auto_deny_firsttime_spammers == true || prompt.auto_deny_firsttime_spammers == true) {
                            try {
                                // await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name,domain,email", item: { _acl: prompt._acl, "report": result, domain:promptdomains, email: promptemails, name: domain, _type: "spam", messageid: envelope.messageId } });
                                await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "domain,config", item: { _acl: prompt._acl, ...result, domain: domain, email: from.toLowerCase(), name: domain + " for " + prompt.name, _type: "spam", messageid: envelope.messageId, config: prompt._id } });
                            } catch (error) {
                                throw error;
                            }
                        }
                    }
                } else {
                    let _whitelist = emails.filter((x) => promptemails.indexOf(x) != -1);
                    addToList(whitelist, _whitelist, exactmatch);
                    _whitelist = emails.filter((x) => promptdomains.indexOf(x.split('@')[1]) != -1);
                    addToList(whitelist, _whitelist, exactmatch);
                    if (prompt.prompt != null && prompt.prompt != "") {
                        await AddMailEvent(client, envelope, null, "scan", result);
                    } else {
                        app.logger.info('ai-spam-check', `id=${envelope.id} Skip scan, prompt is empty`);
                    }
                    if (domaintype == null && prompt.prompt != null && prompt.prompt != "") {
                        if (auto_trust_firsttime_notspam == true || prompt.auto_trust_firsttime_notspam == true) {
                            try {
                                await client.InsertOrUpdateOne({ collectionname: "maildomains", uniqeness: "name,domain,email", item: { _acl: prompt._acl, "report": result, domain: promptdomains, email: promptemails, name: domain, _type: "approved", messageid: envelope.messageId } });
                            } catch (error) {
                                throw error;
                            }
                        }
                    }

                }
            }
        }
        await doScan(false);
        await doScan(true);

        envelope.whitelist = whitelist;
        envelope.quarantinelist = quarantinelist;
        envelope.droplist = droplist;
        sourceDuplicate.pipe(destination).on('error', (err) => {
            app.logger.error('ai-spam-check', 'Error scanning email: %s', err.message);
        });
    });

    done();
}
module.exports.title = 'AI spam checker';
module.exports.init = init;


/**
 * 
 * @param {openiap} client 
 * @param {string} domain
 * @param {string} email
 * @returns 
 */
async function LookupConfigDomain(client, domain, email) {
    if (email != null && email != "") {
        if (Array.isArray(email)) {
            let known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", emails: { "$in": email } } });
            if (known != null) return known;
            const domains = email.map((x) => x.split('@')[1]);
            known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", domains: { "$in": domains } } });
            if (known != null) return known;
        } else {
            let known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", emails: email } });
            if (known != null) return known;
            const _domain = email.split('@')[1];
            known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", domain: _domain } });
            if (known != null) return known;
        }
    }
    if (domain != null && domain != "") {
        if (Array.isArray(domain)) {
            const known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", domains: { "$in": domain } } });
            if (known != null) return known;
        } else {
            const known = await client.FindOne({ collectionname: "mailconfig", query: { _type: "config", domains: domain } });
            if (known != null) return known;
        }
    }
    return null;
}
/**
 * 
 * @param {openiap} client 
 * @param {string} domain
 * @param {string} email
 * @returns 
 */
async function LookupConfigDomains(client, domain, email) {
    if (email != null && email != "") {
        if (Array.isArray(email)) {
            let known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", emails: { "$in": email } } });
            if (known.length > 0) return known;
            const domains = email.map((x) => x.split('@')[1]);
            known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", domains: { "$in": domains } } });
            if (known.length > 0) return known;
        } else {
            let known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", emails: email } });
            if (known.length > 0) return known;
            const _domain = email.split('@')[1];
            known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", domain: _domain } });
            if (known.length > 0) return known;
        }
    }
    if (domain != null && domain != "") {
        if (Array.isArray(domain)) {
            const known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", domains: { "$in": domain } } });
            if (known.length > 0) return known;
        } else {
            const known = await client.Query({ collectionname: "mailconfig", query: { _type: "config", domains: domain } });
            if (known.length > 0) return known;
        }
    }
    return [];
}

//     if (envelope.knowntype != null && envelope.knowntype != "") return envelope.knowntype;
//     if (domain == null || domain == "") {
//         if (envelope.from == null || envelope.from == "") {
//             return "unknown";
//         } 
//         domain = envelope.from.split('@')[1];
//     }
//     if (envelope.knowntype == null && domain != "") {
//         let known = await client.FindOne({ collectionname: "maildomains", query: { name: domain } });
//         if(known == null) {
//             known = await client.FindOne({ collectionname: "domains", query: { name: domain } });
//         }
//         if(known != null) {
//             if(known._type == "relay" || known._type == "disposable" || known._type == "validating") {
//                 envelope.knowntype = known._type;
//                 return envelope.knowntype;
//             }
//         }
//         envelope.knowntype = "unknown";
//         // envelope.knowntype = known != null ? known._type : "unknown";
//     } else if (domain != "") {
//         envelope.knowntype = 'unknown';
//     }
//     return envelope.knowntype;
// }

/**
 * 
 * @param {openiap} client 
 * @param {any} envelope
 * @param {string} type
 * @param {string} action
 * @param {object} report
 */
async function AddMailEvent(client, envelope, info, action, report, err) {
    if (envelope.interface == "bounce") return;
    let id = envelope.id;
    if (id == null && info != null) {
        id = info.id;
    }
    if (id == null) {
        var b = true;
    }
    let from = envelope.from?.toLowerCase() || envelope.mailFrom?.address?.toLowerCase();
    if (envelope.headers != null) {
        let headers = envelope.headers;
        if(envelope.headers.lines) {
            headers = envelope.headers.lines;
        }
        try {
            var headerfrom = headers.find((line) => line.key == "from")?.line.substring(6);
            if (headerfrom != null && headerfrom != "" && headerfrom != envelope.from) {
                var email = headerfrom.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
                var email2 = email[1];
                from = email2;
            }
        } catch (error) {
        }
    }
    let to = envelope.to || envelope.rcptTo?.map(x => x.address);
    if (info != null && info.recipient != null) {
        to = info.recipient;
    } else if (info != null && info.accepted != null && info.accepted.length == 1) {
        to = info.accepted[0];
    }
    if (to == null || to == "") {
        if (envelope.parsedEnvelope != null && envelope.parsedEnvelope.to != null) {
            to = envelope.parsedEnvelope.to;
        } else {
            var b = true;
        }
    }
    if (to != null) {
        if (Array.isArray(to)) {
            to = to.map(x => x.toLowerCase());
        } else {
            to = to.toLowerCase()
        }
    }
    const configs = await LookupConfigDomains(client, null, to);
    var _acl = undefined;
    var _configs = undefined;
    if (configs.length > 0) {
        _acl = [];
        _configs = configs.map(x => x._id);
        for (let n = 0; n < configs.length; n++) {
            const config = configs[n];
            for (let y = 0; y < config._acl.length; y++) {
                let exists = _acl.find((x) => x._id == config._acl[y]._id);
                if (exists == null) {
                    _acl.push(config._acl[y]);
                } else if (exists.rights < config._acl[y].rights) {
                    exists.rights = config._acl[y].rights;
                }
            }

        }
        var b = true;
    }
    const domain = (from != null ? from.split('@')[1] : "unknown");
    if (domain == "unknown") {
        var b = true;
    }
    let todomain = undefined;
    if (to != null && !Array.isArray(to)) {
        todomain = to.split('@')[1];
    } else if (to != null && Array.isArray(to) && to.length == 1) {
        todomain = to[0].split('@')[1];
    }
    let error = undefined;
    if(err != null) {
        try {
            if (typeof err == "string") {
                error = {"message": err.message}
            } else {
                error = JSON.parse(JSON.stringify(err))
            }
        } catch (error) {
            try {
                if(err.message != null) {
                    error = {"message": err.message}
                }
            } catch (error) {
                
            }            
        }
    }
    try {
        var item = {
            _acl, configs: _configs, from, to, id, messageid: envelope.messageId, "_type": action, domain, todomain, action, error,
            name: action + " " + domain
        };
        if (report != null) {
            if (typeof report == "string") {
                item.reason = report;
            } else {
                item = { ...item, ...report }
            }
        }
        if(error != null) {
            item.reason = error.message;
        }
        await client.InsertOne({ collectionname: "mailevents", item});
    } catch (error) {
        app.logger.error('ai-spam-check', 'AddMailEvent: %s', error.message);
    }
}

/**
 * @param {openiap} client 
 * @param {OpenAI} openai 
 * @param {string} model 
 * @param {import('mailparser').ParsedMail} mail
 * @returns 
 */
async function TestMailBody(client, openai, model, mail, userprompt) {
    // console.log(`[AI] Testing email body\n${mailbody.substring(0, 100)}...`);
    // console.log(mailbody);
    if (fake_scan == true) {
        return {
            spam: false,
            confidence: 0.2,
            reason: "Not enough data to make a decision"
        }
    }
    if (userprompt == null || userprompt == "") {
        return {
            spam: false,
            confidence: 1,
            reason: "No user prompt"
        }
    }
    const systemmessage = {
        role: 'system',
        content: `Title: Email Spam Detection Assistant
Prompt:
Define Spam: User will provide a detailed definition of what you should consider to be spam in emails. Include specific characteristics, keywords, or patterns that you associate with spam.
Email Content: After defining spam, user will paste the content of the email the inquiring is about.
Instructions for the AI: With the provided definition of spam in mind, analyze the content of the submitted email. Consider factors such as the presence of specific keywords, the nature of the email (unsolicited or bulk), and any patterns or characteristics mentioned in the user's definition of spam. Then, provide a concise evaluation of whether the email should be considered spam based on the criteria provided.
Response from AI: The AI will first reiterate the user-defined characteristics of spam for clarity. Then, it will analyze the email content, highlighting any elements that match the spam criteria and concluding with an assessment of whether the email is spam.        
You reply must be in the following JSON format, where confidence is a number between 0 and 1 where 1 is very confident in your assesment and 0 you have no idea if this is spam or not.
{
    "spam": true,
    "confidence": 0.9,
    "reason": "The reason why you consider it spam"
}`}

    const mailbody = `Subject: ${mail.subject}\n${mail.text || mail.html}`;
    const usermessage = {
        role: 'user',
        content: userprompt
    }
    const emailmessage = {
        role: 'user',
        content: `Please analyze the following email based on what is generally consider spam or scam and include my specefic definition of spam:\n` + mailbody
    }
    const chatCompletion = await openai.chat.completions.create({
        messages: [systemmessage, usermessage, emailmessage],
        model: model,
        response_format: { type: 'json_object' }
    });
    return JSON.parse(chatCompletion.choices[0].message.content);
}
