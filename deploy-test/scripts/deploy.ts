import { ethers } from "hardhat";
import { readFile } from "./readFile";

async function main() {
  const halo2verifyingKeyFactory = await ethers.getContractFactory("Halo2VerifyingKey");
  const halo2verifyingKey = await halo2verifyingKeyFactory.deploy();
  const halo2VerifierFactory = await ethers.getContractFactory("Halo2Verifier");
  const halo2Verifier = await halo2VerifierFactory.deploy();
  await halo2verifyingKey.deployed();
  await halo2Verifier.deployed();
  console.log("Halo2VerifyingKey deployed to:", halo2verifyingKey.address);
  console.log("Halo2Verifier deployed to:", halo2Verifier.address);
  const proof = await readFile("./contracts/generated/proof.txt");
  const tx = await halo2Verifier.verifyProof(halo2verifyingKey.address, proof, []);
  console.log("tx hash:", tx.hash);
  console.log("Proof verified");
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})

