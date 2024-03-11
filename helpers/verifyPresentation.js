const { canonicalize } = require('json-canonicalize');
const { Web3 } = require('web3');
const contractABI = require('../abi/WideSignatureLogger.json').abi;

async function verifyPresentation(data) {
    try {
        const web3 = new Web3(process.env.WEB3_ENDPOINT);
        const contractAddress = process.env.WIDE_CONTRACT;

        const contract = new web3.eth.Contract(contractABI, contractAddress);

        const decryptedPayloadFromClient = data.credentialSubject.issuerDomains[0].data.credentials.reduce((acc, { name, value }) => {
            acc[name] = value; return acc;
        }, {});

        //DEV: Uncomment to test verification failure
        //decryptedPayloadFromClient.city = 'narnia';

        const message = {
            publicKey: data.credentialSubject.id,
            encPayloadHash: data.credentialSubject.issuerDomains[0].data.payloadKeccak256CipherText,
            payloadHash: web3.utils.keccak256(JSON.stringify(canonicalize(decryptedPayloadFromClient)))
        };

        const jsonMessage = JSON.stringify(canonicalize(message));
        const messageHash = web3.utils.keccak256(jsonMessage);

        const owner = await contract.methods.owner().call();

        const payloadResponse = await contract.methods.payloads(messageHash).call();

        const recoveredSignature = web3.eth.accounts.recover(jsonMessage, payloadResponse.signature);

        return recoveredSignature.toLocaleLowerCase() === process.env.WIDE_PUB_KEY.toLocaleLowerCase();
    } catch (error) {
        console.error('Failed when attempting to verify signature:', error);
        throw new Error('Failed to verify authenticity of presented data.');
    }
}

module.exports = verifyPresentation;