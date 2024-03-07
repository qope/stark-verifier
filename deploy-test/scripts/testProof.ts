import { ethers } from "hardhat";
import { readFile } from "./readFile";

const halo2VerifyingKeyAddress = ""
const halo2VerifierAddress = ""

async function main() {
    const halo2Verifier = await ethers.getContractAt("Halo2Verifier", halo2VerifierAddress);
    const proof = await readFile("./contracts/generated/proof.txt");
    await halo2Verifier.verifyProof(halo2VerifyingKeyAddress, proof, []);
    console.log("Proof verified");
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})