const { compiler } = require("circom");
const { Circuit, groth ,stringifyBigInts } = require("snarkjs");
const path = require("path");
const fs = require("fs");

const genKeypair = async () => {
  console.log("start....");
  
  console.log("Get circtui definition....");
  const circuitDef = await compiler(  
	path.join(__dirname, "./withdraw.circom"),{}
  );
  const circuit = new Circuit(circuitDef);
  
  console.log("Setup....");
  const {vk_proof,vk_verifier} = groth.setup(circuit);
  //save pk,vk file
  fs.writeFileSync("proving_key.json", JSON.stringify(stringifyBigInts(vk_proof)), 'utf8');
  fs.writeFileSync("verification_key.json", JSON.stringify(stringifyBigInts(vk_verifier)), 'utf8');

  console.log("finish....");
  process.exit(0);
};

genKeypair();
