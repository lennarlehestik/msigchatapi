const { Api, JsonRpc, Serialize } = require('eosjs');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { TextDecoder, TextEncoder } = require('util');

const rpc = new JsonRpc('https://wax.eosusa.io', { fetch });

const api = new Api({
  rpc,
  textDecoder: new TextDecoder(),
  textEncoder: new TextEncoder(),
});

(async () => {
  try {
    const hexData = '90A7A608193FA78A0000000000904D430100000000000000045741580000000009736F6D65206D656D6F';

    const { abi } = await rpc.get_abi('eosio.token');

    const buffer = new Serialize.SerialBuffer({
      textEncoder: api.textEncoder,
      textDecoder: api.textDecoder,
    });

    buffer.pushArray(Buffer.from(hexData, 'hex'));

    // Manually create types
    const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), abi);
    const actionType = types.get('transfer');

    const deserializedActionData = actionType.deserialize(buffer);

    console.log('Memo:', deserializedActionData.memo);

  } catch (error) {
    console.error('Error:', error);
  }
})();
