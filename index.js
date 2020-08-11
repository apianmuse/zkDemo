
//const {
//  zkIdentityAddress
//} = require("zk-contracts/build/DeployedAddresses.json");
//const zkIdentityDef = require("zk-contracts/build/ZkIdentity.json");

const { binarifyWitness } = require("./utils/binarify");
const bigInt = require("big-integer");
const { compiler } = require("circom");
const { Circuit, groth ,stringifyBigInts ,unstringifyBigInts} = require("snarkjs");
const path = require("path");
const fs = require("fs");

//const { ethers } = require("ethers");
//// Provider to interact with ganache
//const provider = new ethers.providers.JsonRpcProvider("http://localhost:7545");
//const wallet = new ethers.Wallet(
//  "0x954a65BbD759AE33Aa9FAF595131A3EC90909Cc2",
//  provider
//);
//const zkIdentityContract = new ethers.Contract(
//  zkIdentityAddress,
//  zkIdentityDef.abi,
//  wallet
//);


const SNARK_FIELD_SIZE = bigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

//read input
const fileData = fs.readFileSync('input.json');
const inputObj = JSON.parse(fileData);
const root = bigInt(inputObj.root);
const nullifierHash = bigInt(inputObj.nullifierHash);
const secret =  bigInt(inputObj.secret);
const paths2_root = [
	bigInt(inputObj.paths2_root[0]),
	bigInt(inputObj.paths2_root[1]),
	bigInt(inputObj.paths2_root[2])
];
const paths2_root_pos = bigInt(inputObj.paths2_root_pos);

const provingKey = require("./proving_key.json");
const verifyingKey = require("./verification_key.json");

//gen wintness proof
const generateProofAndVerify = async circuitInputs => {
  console.log("Get circtui definition....");
  const circuitDef = await compiler(  
	path.join(__dirname, "./withdraw.circom"),{}
  );
  const circuit = new Circuit(circuitDef);
  
  console.log("loading pk,vk....");
  const vk_proof = unstringifyBigInts(provingKey);
  const vk_verifier = unstringifyBigInts(verifyingKey);

  console.log("Generating witness....");
  const witness = circuit.calculateWitness(stringifyBigInts(circuitInputs));  
  //save witness file
  const witnessString = witness.map(x => x.toString());
  fs.writeFileSync("witness.json",JSON.stringify(witnessString));   

  console.log("Generating proof and publicSignals....");
  const {proof,publicSignals} = await groth.genProof(vk_proof,witness); 
  //save proof file
  const proofJson = JSON.stringify({
	    pi_a: stringifyBigInts(proof.pi_a).slice(0, 3),
		pi_b: stringifyBigInts(proof.pi_b).slice(0, 3), 
		pi_c: stringifyBigInts(proof.pi_c).slice(0, 3),
		protocol: "groth"
	});
  fs.writeFileSync("proof.json", proofJson);
   //save public file
  console.log("Generating public.json....");
  const  pS = publicSignals.map(x => bigInt(x));
  const publicInputs = pS.map(x => x.mod(SNARK_FIELD_SIZE).toString());
  console.log("Generating public.json....");
  const publicJson = [
     publicInputs[0],publicInputs[1]
  ];
  fs.writeFileSync("public.json", JSON.stringify(publicJson)); 
 
  
  console.log("Check isValid....");
  const isValid = groth.isValid(vk_verifier,proof,publicSignals);
  console.log(`Passed local zk-snark verification: ${isValid}`);
   
   
  console.log("Generating solidityProof....");
  const solidityProof = {
    a: stringifyBigInts(proof.pi_a).slice(0, 2),
    b: stringifyBigInts(proof.pi_b).slice(0, 2),
    c: stringifyBigInts(proof.pi_c).slice(0, 2),
    inputs: publicInputs
  };
  //save solidityProof file
  fs.writeFileSync("solidityProof.json", JSON.stringify(solidityProof)); 

  //// Submit to smart contract
  //const solidityIsValid = await zkIdentityContract.isInGroup(
  //  solidityProof.a,
  //  solidityProof.b,
  //  solidityProof.c,
  //  solidityProof.inputs
  //);
  //console.log(`Verified user is in group (via solidity): ${solidityIsValid}`);
  
};

const main = async () => {
  console.log("zkp start....");

  await generateProofAndVerify({
    root: root,
    nullifierHash: nullifierHash,
	secret: secret,
	paths2_root: paths2_root,
	paths2_root_pos: paths2_root_pos
  });

  console.log("zkp finish....");
  process.exit(0);
};

main();
