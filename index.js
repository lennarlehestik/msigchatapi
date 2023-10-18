const express = require('express');
const bodyParser = require('body-parser');
const { Api, JsonRpc, Serialize, RpcError } = require('eosjs');
const { JsSignatureProvider } = require('eosjs/dist/eosjs-jssig');
const { TextEncoder, TextDecoder } = require('util');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const cors = require('cors');
const WebSocket = require('ws');
const crypto = require('crypto');

const app = express();
app.use(cors());

app.use(bodyParser.json());


const endpoint = "https://wax.eosusa.io"

const defaultPrivateKey = process.env.PRIVATE_KEY;
const privateKeys = [defaultPrivateKey];
const signatureProvider = new JsSignatureProvider(privateKeys);

const rpc = new JsonRpc('https://wax.eosusa.io/', { fetch });

const api = new Api({ rpc, signatureProvider, textDecoder: new TextDecoder(), textEncoder: new TextEncoder() });
const wss = new WebSocket.Server({ noServer: true });

const submitMessage = async(message, accountName, community) => {
    try {
        const result = await api.transact({
            actions: [{
                account: 'chat',
                name: 'sendmessage',
                authorization: [{
                    actor: 'chat',
                    permission: 'custom',
                }],
                data: {
                    message: message,
                    user: accountName,
                    chat_account: community
                },
            }],
        }, {
            blocksBehind: 3,
            expireSeconds: 30,
        });

        console.dir(result);
    } catch (e) {
        if (e instanceof RpcError) {
            console.error(JSON.stringify(e.json, null, 2));
        } else {
            console.error(e);
        }
    }
}


const initialMemoVerification = async (serializedTransaction, expectedMemo) => {
    try {
        const serializedTransactionUint8Array = new Uint8Array(Object.values(serializedTransaction));

        // Deserialize the transaction
        const deserializedTransaction = api.deserializeTransaction(serializedTransactionUint8Array);
        console.log('Deserialized Transaction:', deserializedTransaction);
        console.log(deserializedTransaction.actions[0].data)

        const { abi } = await rpc.get_abi('eosio.token');

        const buffer = new Serialize.SerialBuffer({
          textEncoder: api.textEncoder,
          textDecoder: api.textDecoder,
        });
    
        buffer.pushArray(Buffer.from(deserializedTransaction.actions[0].data, 'hex'));
    
        // Manually create types
        const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), abi);
        const actionType = types.get('transfer');
    
        const deserializedActionData = actionType.deserialize(buffer);
    
        console.log('Memo:', deserializedActionData.memo);
        console.log('Expected Memo:', expectedMemo)

        // Validate the memo
        if (deserializedActionData.memo === expectedMemo) {
            console.log("The memo is valid");
            return true
        } else {
            console.log("The memo is invalid");
            return false
        }
    } catch (error) {
        console.error('Error:', error.message);
    }
}

const signatureVerification = async(accountName, serializedTransaction) => {
    const accountInfo = await rpc.get_account(accountName);

    // Extract public keys from the account information
    const publicKeys = accountInfo.permissions.map(perm => perm.required_auth.keys[0].key);

    // Determine which keys are required to sign the transaction
    const requiredKeys = await api.authorityProvider.getRequiredKeys({ transaction: serializedTransaction, availableKeys: publicKeys });
    
    // Validate the signatures
    const isTransactionValid = requiredKeys.every(key => signatures.includes(key));
    return isTransactionValid;
}

const msigVerification = async(accountName, serializedTransaction, community, permission) => {    
    // Check if account is in msig
    const data = await rpc.get_account(community);
    console.log(data.permissions)
    const permissions = data.permissions.filter(perm => perm.perm_name === permission)[0].required_auth.accounts;
    const actorExists = permissions.some(permission => permission.permission.actor === accountName);

    console.log("Account in msig:" + actorExists);
    return actorExists;
}

const fetchMessagesFromChain = async (community) => {
    try {
        const response = await fetch(`${endpoint}/v1/chain/get_table_rows`, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                json: true,
                code: "chat",
                table: "messages",
                scope: community,
                limit:1000
            }),
        });

        const data = await response.json();

        // Decrypt messages if necessary
        data.rows.forEach(row => {
            if(isEncrypted(row.message)) {
                row.message = decrypt(row.message, community);
            }
        });

        return data;
    } catch (error) {
        console.error("Error fetching messages:", error);
        throw error;  // or return an error object if you prefer
    }
}

const isEncrypted = (message) => {
    const parts = message.split(':');
    return parts.length === 3 && parts[0].length === 32 && parts[1].length === 32;
}

const generateMemo = () => {
    return crypto.randomBytes(32).toString('hex');
}

// Replace this with your own secret key
const SALT = defaultPrivateKey;

function getKey(communityName) {
    // Derive a 256-bit key from the community name using PBKDF2
    return crypto.pbkdf2Sync(communityName, SALT, 100000, 32, 'sha256');
}


function encrypt(text, communityName) {
    const iv = crypto.randomBytes(16);
    const key = getKey(communityName);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

function decrypt(data, communityName) {
    const [ivHex, authTagHex, encryptedHex] = data.split(':');
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    
    const key = getKey(communityName);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

const checkIfCanDeleteMessages = async (community) => {
    try {
        const response = await fetch(`${endpoint}/v1/chain/get_table_rows`, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                json: true,
                code: "chat",
                table: "delapproval",
                scope: "chat",
                lower_bound: community,
                upper_bound: community
            }),
        });

        const data = await response.json();
        if(data?.rows[0].approved_to_delete == 1){
            return true
        }
        else{
            return false
        }
    } catch (error) {
        console.error("Error fetching messages:", error);
        throw error;  // or return an error object if you prefer
    }
}

const deleteMessages = async (community, amount) => {
    try {
        const result = await api.transact({
            actions: [{
                account: 'chat',
                name: 'delmessages',
                authorization: [{
                    actor: 'chat',
                    permission: 'custom',
                }],
                data: {
                    chat_account: community,
                    number_of_messages: amount
                },
            }],
        }, {
            blocksBehind: 3,
            expireSeconds: 30,
        });

        console.dir(result);
    } catch (e) {
        if (e instanceof RpcError) {
            console.error(JSON.stringify(e.json, null, 2));
        } else {
            console.error(e);
        }
    }
}

const deleteCommunity = async (community) => {
    try {
        const result = await api.transact({
            actions: [{
                account: 'chat',
                name: 'delchat',
                authorization: [{
                    actor: 'chat',
                    permission: 'custom',
                }],
                data: {
                    chat_account: community,
                },
            }],
        }, {
            blocksBehind: 3,
            expireSeconds: 30,
        });

        console.dir(result);
    } catch (e) {
        if (e instanceof RpcError) {
            console.error(JSON.stringify(e.json, null, 2));
        } else {
            console.error(e);
        }
    }
}

const editCommunity = async (chat_account, accountName, permission, community_profile_img_url, community_background_img_url, description) => {
    try {
        const result = await api.transact({
            actions: [{
                account: 'chat',
                name: 'setchat',
                authorization: [{
                    actor: 'chat',
                    permission: 'custom',
                }],
                data: {
                    chat_account: chat_account,
                    adder: accountName,
                    permission: permission,
                    community_profile_img_url: community_profile_img_url,
                    community_background_img_url: community_background_img_url,
                    description: description
                },
            }],
        }, {
            blocksBehind: 3,
            expireSeconds: 30,
        });

        console.dir(result);
    } catch (e) {
        if (e instanceof RpcError) {
            console.error(JSON.stringify(e.json, null, 2));
        } else {
            console.error(e);
        }
    }
}

wss.on('connection', (ws, req) => {
    console.log('Client connected');

    // Generate and send a memo to the client
    const memo = generateMemo();
    console.log(JSON.stringify({ memo }))
    ws.send(JSON.stringify({ memo, type:'memo' }));

    // Initialize a custom property to store verification status per community
    ws.verifiedCommunities = {};
    // Initialize a custom property to store the last verified community
    ws.lastVerifiedCommunity = null;

    // Send messages to the connected user every 20 seconds
    const messageInterval = setInterval(async () => {
        // Only send messages if the user has a last verified community
        if(ws.lastVerifiedCommunity) {
            try {
                const messages = await fetchMessagesFromChain(ws.lastVerifiedCommunity);
                ws.send(JSON.stringify(messages));
            } catch (error) {
                console.error("Error sending messages:", error);
            }
        }
    }, 5000);

    ws.on('message', async (message) => {
        console.log('Received:', message);
        const {type, payload} = JSON.parse(message);

        if(type == "TRANSACTION_VERIFICATION"){
            const { serializedTransaction, signatures, accountName, community, permission} = payload;
            try {
                const userOwnsAccount = await initialMemoVerification(serializedTransaction, memo);
                console.log(userOwnsAccount)
                const accountInMsig = await msigVerification(accountName, serializedTransaction, community, permission)
                const userSignedTransaction = await signatureVerification(accountName, serializedTransaction)

                if(accountInMsig && userOwnsAccount && userSignedTransaction) {
                    console.log('Transaction verified successfully');
                    // Update the verification status
                    ws.lastVerifiedCommunity = community;
                    try {
                        const messages = await fetchMessagesFromChain(community);
                        ws.send(JSON.stringify({ type:"VERIFICATION_SUCCESS", verified: true }));
                        ws.send(JSON.stringify(messages));
                    } catch (error) {
                        console.error("Error sending messages to client:", error);
                    }
                } else {
                    ws.close(1008, 'Transaction verification failed or not in msig.');
                }
                
            } catch (error) {
                console.error(error);
                ws.send(JSON.stringify({ type: 'FAILED_TO_VERIFY', message:"Failed to verify transaction." }));
                ws.close(1011, 'Failed to verify transaction');
            }
        } else if(type == "SEND_MESSAGE") {
            // Check the verification status before allowing message sending
            if(!ws.lastVerifiedCommunity) {
                console.error("User not verified. Cannot send messages.");
                ws.send(JSON.stringify({ error: 'User not verified. Cannot send messages.' }));
                return;
            }

            const { message, accountName, community } = payload;
            try {
                const encryptedMessage = encrypt(message, community);
                await submitMessage(encryptedMessage, accountName, community);
                const messages = await fetchMessagesFromChain(community);
                ws.send(JSON.stringify(messages));
            } catch (error) {
                console.error("Error submitting message:", error);
            }
        } else if(type == "DELETE_MESSAGES") {
            // Check the verification status before allowing message sending
            if(!ws.lastVerifiedCommunity) {
                console.error("User not verified. Cannot delete messages.");
                ws.send(JSON.stringify({ error: 'User not verified. Cannot delete messages.' }));
                return;
            }
            const { amount, community } = payload;
            const canDelete = await checkIfCanDeleteMessages(community)
            if(canDelete) {
                try{
                    await deleteMessages(community, amount)
                    const messages = await fetchMessagesFromChain(community);
                    ws.send(JSON.stringify(messages));
                }
                catch (error) {
                    console.error("Error deleting messages:", error);
                    ws.send(JSON.stringify({ error: 'Cannot delete messages.' }));
                }
            }
            else{
                ws.send(JSON.stringify({ error: 'Cannot delete messages, check if deleting is enabled.' }));
            }
        } else if(type == "DELETE_COMMUNITY") {
            // Check the verification status before allowing message sending
            if(!ws.lastVerifiedCommunity) {
                console.error("User not verified. Cannot delete messages.");
                ws.send(JSON.stringify({ error: 'User not verified. Cannot delete messages.' }));
                return;
            }
            const { community } = payload;
            const canDelete = await checkIfCanDeleteMessages(community)
            if(canDelete) {
                try{
                    await deleteCommunity(community)
                    const messages = await fetchMessagesFromChain(community);
                    ws.send(JSON.stringify(messages));
                }
                catch (error) {
                    console.error("Error deleting messages:", error);
                    ws.send(JSON.stringify({ error: 'Cannot delete messages.' }));
                }
            }
            else{
                ws.send(JSON.stringify({ error: 'Cannot delete messages, check if deleting is enabled.' }));
            }
        } else if(type == "EDIT_COMMUNITY") {
            // Check the verification status before allowing message sending
            if(!ws.lastVerifiedCommunity) {
                console.error("User not verified. Cannot delete messages.");
                ws.send(JSON.stringify({ error: 'User not verified. Cannot delete messages.' }));
                return;
            }
            const { accountName, permission, community_profile_img_url, community_background_img_url, description  } = payload;
            try{
                editCommunity(ws.lastVerifiedCommunity, accountName, permission, community_profile_img_url, community_background_img_url, description)
            }
            catch (error) {
                console.error("Error editing community:", error);
                ws.send(JSON.stringify({ error: 'Cannot edit community.' }));
            }
        } else if(type == "ping") {
            console.log("ping received")
        }
    });

    ws.on('close', () => {
        console.log('Connection closed');
        clearInterval(messageInterval);

    });
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});

server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});
