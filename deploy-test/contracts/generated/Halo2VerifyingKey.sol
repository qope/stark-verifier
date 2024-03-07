// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(
                0x0000,
                0x1cccc90de2f52aa73e0d5409dc4e554451b81b1133fabdf58160dd5451721447
            ) // vk_digest
            mstore(
                0x0020,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_instances
            mstore(
                0x0040,
                0x0000000000000000000000000000000000000000000000000000000000000011
            ) // k
            mstore(
                0x0060,
                0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801
            ) // n_inv
            mstore(
                0x0080,
                0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea
            ) // omega
            mstore(
                0x00a0,
                0x193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb
            ) // omega_inv
            mstore(
                0x00c0,
                0x299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4
            ) // omega_inv_to_l
            mstore(
                0x00e0,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // has_accumulator
            mstore(
                0x0100,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // acc_offset
            mstore(
                0x0120,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limbs
            mstore(
                0x0140,
                0x0000000000000000000000000000000000000000000000000000000000000000
            ) // num_acc_limb_bits
            mstore(
                0x0160,
                0x0000000000000000000000000000000000000000000000000000000000000001
            ) // g1_x
            mstore(
                0x0180,
                0x0000000000000000000000000000000000000000000000000000000000000002
            ) // g1_y
            mstore(
                0x01a0,
                0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
            ) // g2_x_1
            mstore(
                0x01c0,
                0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
            ) // g2_x_2
            mstore(
                0x01e0,
                0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
            ) // g2_y_1
            mstore(
                0x0200,
                0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
            ) // g2_y_2
            mstore(
                0x0220,
                0x0c32cb17dbbb875cc439c9f83323c78897d2a571b4f5e4dfb862475a46be0e68
            ) // neg_s_g2_x_1
            mstore(
                0x0240,
                0x03dd18b75869a6d41475b2976b63b7c3a1a50c639038c2dc55c901373d05771b
            ) // neg_s_g2_x_2
            mstore(
                0x0260,
                0x10b4e8c8c6854f03e9cf54897655f49df9bc3052a8f0c46017ef16c74b7e091a
            ) // neg_s_g2_y_1
            mstore(
                0x0280,
                0x03f8eaf4883721d8469a8d304c06716eeb12103ee2962b6cb20b95a55f2e0005
            ) // neg_s_g2_y_2
            mstore(
                0x02a0,
                0x0067a64adf371e476a15a9b785f73b0ecdd539547b5b933f7cf2db3a925936d3
            ) // fixed_comms[0].x
            mstore(
                0x02c0,
                0x16db57815db484a9418a3efac5ea430bad9b11c0fefaf5b0d641b638b26db783
            ) // fixed_comms[0].y
            mstore(
                0x02e0,
                0x1a106fc5da7495c6a469943fc6edb41d360c8dfdc3f7ba029cc4b614e22a6705
            ) // fixed_comms[1].x
            mstore(
                0x0300,
                0x0db47daea9f90110d879e0b1f904a4f6cffc8ff72e9aed334e97ce1c0007920f
            ) // fixed_comms[1].y
            mstore(
                0x0320,
                0x12e2bbda1b4d4a32a561fa6cbffa976808e006be60748c709128b68f17beee72
            ) // fixed_comms[2].x
            mstore(
                0x0340,
                0x134b9f6a8e615cd6c869c049636c98b7328ddc2be79bc9647fbb0bdf3720dc7b
            ) // fixed_comms[2].y
            mstore(
                0x0360,
                0x1adaa10595115fc3297cb8eee999ba5f3a0c033609d176d7f5530327ccd71b30
            ) // fixed_comms[3].x
            mstore(
                0x0380,
                0x14a4f776625f17f1058d2f83dff956effa08ceaffe8f9f0d727f8ceed503ea42
            ) // fixed_comms[3].y
            mstore(
                0x03a0,
                0x0ad8505931e5cdcdac86904e4b79501458d1e07430872b6d87d404fed26952f1
            ) // permutation_comms[0].x
            mstore(
                0x03c0,
                0x27d031ae97b4794acda81fa0923d81c28db5621a07948b4e055a57e52a4d9690
            ) // permutation_comms[0].y
            mstore(
                0x03e0,
                0x15edea97cd950201a0be712287314c00be14e601a6c4212a1a10c06f5b6ef1b6
            ) // permutation_comms[1].x
            mstore(
                0x0400,
                0x0df9afb948dd068ff6078e4bf84b1dabd3a994d26d3d5ce2a9668504b42eb972
            ) // permutation_comms[1].y
            mstore(
                0x0420,
                0x1d3d428fcdcb89fc6ddcab2e0c83a374ac3c73559127dae378b2a87913626c01
            ) // permutation_comms[2].x
            mstore(
                0x0440,
                0x0513775c62a3f58ef8ff29963e3cf04fac133c2e23cd66c5530717cf2933072a
            ) // permutation_comms[2].y
            mstore(
                0x0460,
                0x2576f4de662f285cb1858215fe2cc6a90d18942736d434b37cba3544e2ccc8a5
            ) // permutation_comms[3].x
            mstore(
                0x0480,
                0x2ba508a73a722989a8d2c064cc538c623faa22d5da4271cb3b13f2705c3d204f
            ) // permutation_comms[3].y
            mstore(
                0x04a0,
                0x16228011acf2d982c97fc6a7ba6b90f6fbfe9d846ff1fe470ba0da46c0d6af53
            ) // permutation_comms[4].x
            mstore(
                0x04c0,
                0x1078020c48ae6ea015e6bb001f9d1ad354f044b5ccd3ff0418a8d31788d54498
            ) // permutation_comms[4].y
            mstore(
                0x04e0,
                0x0e80a48069e20a6dbe5d7e4a33b1661477d935ccdd438f2c87d865b9d5d0de4c
            ) // permutation_comms[5].x
            mstore(
                0x0500,
                0x2e4015e234129cf8cb06bf4798c255783b6c4ae3bab4ab99271ef0f5164db11a
            ) // permutation_comms[5].y
            mstore(
                0x0520,
                0x24ccc385009f495d5ad259a6f942f2a3abf892774329b7b09b5fe65d623e0917
            ) // permutation_comms[6].x
            mstore(
                0x0540,
                0x12752fcac44a138829b67b60172b10b151373f9a8f41bb4a929a6e70f0df4d2e
            ) // permutation_comms[6].y

            return(0, 0x0560)
        }
    }
}
