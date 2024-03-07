// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x08f2057e3a36a191022513ef5ac80794aa86d185cfab824b7f8967d674f8acde) // vk_digest
            mstore(0x0020, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_instances
            mstore(0x0040, 0x0000000000000000000000000000000000000000000000000000000000000011) // k
            mstore(0x0060, 0x30643640b9f82f90e83b698e5ea6179c7c05542e859533b48b9953a2f5360801) // n_inv
            mstore(0x0080, 0x304cd1e79cfa5b0f054e981a27ed7706e7ea6b06a7f266ef8db819c179c2c3ea) // omega
            mstore(0x00a0, 0x193586da872cdeff023d6ab2263a131b4780db8878be3c3b7f8f019c06fcb0fb) // omega_inv
            mstore(0x00c0, 0x299110e6835fd73731fb3ce6de87151988da403c265467a96b9cda0d7daa72e4) // omega_inv_to_l
            mstore(0x00e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
            mstore(0x0100, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
            mstore(0x0120, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
            mstore(0x0140, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
            mstore(0x0160, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
            mstore(0x0180, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
            mstore(0x01a0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
            mstore(0x01c0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
            mstore(0x01e0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
            mstore(0x0200, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
            mstore(0x0220, 0x09e1f52b5208b31864bf356adc4dbe7cf485a8bdf4c2b77b3d9e6b9116880edc) // neg_s_g2_x_1
            mstore(0x0240, 0x20b8ace6221507dd2c8a27e39be56f9bf6b7dda42b07a132327187b3e01735d9) // neg_s_g2_x_2
            mstore(0x0260, 0x04dd2c1182f0bcc2c8525a5d3307b8675242f1f9515ed59d5b37b34fed6755a2) // neg_s_g2_y_1
            mstore(0x0280, 0x10d9da155c518205366e5f4637ff9f81ce26d69a1fd63d092ce15a9c02cfc6dc) // neg_s_g2_y_2
            mstore(0x02a0, 0x10df36bee8cb829a11881c9ae75f6cf40a9f0fdc1000e02b2b31eac8c891ff6c) // fixed_comms[0].x
            mstore(0x02c0, 0x0350690a0441a0d91dbbfc8a2ae3e4582893178f263f94c373a4be06e7c08b92) // fixed_comms[0].y
            mstore(0x02e0, 0x14cc937b41cf22ce29800b042a1bf282fa8ef38ce4c7275b295f11f29ebbe286) // fixed_comms[1].x
            mstore(0x0300, 0x0d971371fe395198b8ff48d0ad3a0b6e5c32645237c2939834599865b8946a74) // fixed_comms[1].y
            mstore(0x0320, 0x257f754f418a75d9f208de5986462505270db879126af2a708e705f5251803a2) // fixed_comms[2].x
            mstore(0x0340, 0x2c4effdfb09167a5ee0cc765640603163683d83baa6d7aa588e238a1824903ed) // fixed_comms[2].y
            mstore(0x0360, 0x10aa43b666e3dc83ae70fdaa6f53463bdce28216e93b61bda23d520769c52071) // fixed_comms[3].x
            mstore(0x0380, 0x0e9b0a06e2fc7e044d77370a69173acfb05aa72c674e854a16a54c9e93aa0624) // fixed_comms[3].y
            mstore(0x03a0, 0x0743e2b4d1a8730c5e85d516d125fd161244dfdcc8c32c80d6cded0108887f1d) // permutation_comms[0].x
            mstore(0x03c0, 0x197cc8d82b2f8f9a0b434fa43cc10274333730244ebf9be0b3963eff9a0c2cf2) // permutation_comms[0].y
            mstore(0x03e0, 0x0df7c20c79d043a3114a9e63f33b817ee34d140840d3d034ba8cbc91db5d9c98) // permutation_comms[1].x
            mstore(0x0400, 0x2a2161883abd7edf182adc234e230a6b1e3089452b0b43b685e4c52da8e328bc) // permutation_comms[1].y
            mstore(0x0420, 0x0e600ed9688775cd78924b277e85c34b10ee8cbae0f1c00b3c0702044c7a624a) // permutation_comms[2].x
            mstore(0x0440, 0x00fada86abbb6d70e8c436bc8b7ed8e16366bef097933021aaaaa7b36079bd4d) // permutation_comms[2].y
            mstore(0x0460, 0x138bc735d16e2521992973e7e8ecee8ffb501fb047aa54a87a80caa68aa97939) // permutation_comms[3].x
            mstore(0x0480, 0x28232d5a64fc1de04bb468ffabaf2b6a71f5a264a7d0a6a9361e86abc6612552) // permutation_comms[3].y
            mstore(0x04a0, 0x09125c7ad0aacfa7c85b7a97b931bb7eea768a3ff32575ecaca2390d9b9e9491) // permutation_comms[4].x
            mstore(0x04c0, 0x1751796e91ff61b6f91eb0f3b40b35b11004cb496f550f6802fd3f23bdbdff03) // permutation_comms[4].y
            mstore(0x04e0, 0x22eb5b57cc1059c79a29ac3df6e4d291eea0bd1e4bb8fa9976fdd5769bfe2f1b) // permutation_comms[5].x
            mstore(0x0500, 0x1e756eef20e3a4b748138a60fe563261b34da5827fe536175dd3a2ce68ffc81c) // permutation_comms[5].y
            mstore(0x0520, 0x0c9d2360049a1f8ac70286041b3fe8445bdcac2dd1e983c75182568ea9f2a971) // permutation_comms[6].x
            mstore(0x0540, 0x22f2773a606fdcb654708b0cbb2263d68c4baf40719633168a9544d9dcb5284a) // permutation_comms[6].y

            return(0, 0x0560)
        }
    }
}