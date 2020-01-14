#include <string.h>
#include "kernel.h"
#include "functions.h"
#include "internal.h"
#include "misc.h"
#include "rangeproof.h"
#include "sign.h"

// sk0_J is a result of multiplication of derived key and generator J
void switch_commitment_get_sk1(const secp256k1_gej* commitment,
                               const secp256k1_gej* sk0_j,
                               secp256k1_scalar* scalar_out) {
    beam_sha256_ctx x;
    beam_hash_sha256_init(&x);

    point_t commitment_point;
    export_gej_to_point((secp256k1_gej*)commitment, &commitment_point);

    point_t sk0_j_point;
    export_gej_to_point((secp256k1_gej*)sk0_j, &sk0_j_point);

    beam_hash_sha256_update(&x, commitment_point.x, DIGEST_LENGTH);
    beam_hash_sha256_write_8(&x, commitment_point.y);
    beam_hash_sha256_update(&x, sk0_j_point.x, DIGEST_LENGTH);
    beam_hash_sha256_write_8(&x, sk0_j_point.y);

    uint8_t scalar_res[32];
    beam_hash_sha256_final(&x, scalar_res);
    scalar_import_nnz(scalar_out, scalar_res);
}

void switch_commitment(const uint8_t* asset_id, secp256k1_gej* h_gen) {
    if (asset_id && !(memis0(asset_id, 32))) {
        beam_sha256_ctx oracle;
        beam_hash_sha256_init(&oracle);
        beam_hash_sha256_update(&oracle, (const uint8_t*)"a-id", 5);
        beam_hash_sha256_update(&oracle, asset_id, 32);

        point_t pt;
        pt.y = 0;

        do {
            beam_hash_sha256_update(&oracle, (const uint8_t*)"a-gen", 6);

            beam_sha256_ctx new_oracle;
            memcpy(&new_oracle, &oracle, sizeof(beam_sha256_ctx));
            beam_hash_sha256_final(&new_oracle, pt.x);

            beam_hash_sha256_update(&oracle, pt.x, DIGEST_LENGTH);
        } while (!point_import_nnz(h_gen, &pt));
    } else {
        secp256k1_gej_set_infinity(h_gen);
    }
}

void create_common_kidv_image(const HKdf_t* kdf, const key_idv_t* kidv,
                              secp256k1_gej* out_commitment) {
    uint8_t hash_id[DIGEST_LENGTH];
    generate_hash_id(kidv->id.idx, kidv->id.type, kidv->id.sub_idx, hash_id);

    secp256k1_scalar sk;
    derive_key(kdf->generator_secret, DIGEST_LENGTH, hash_id, DIGEST_LENGTH,
               &kdf->cofactor, &sk);

    // Multiply key by generator G
    generator_mul_scalar(out_commitment, get_context()->generator.G_pts, &sk);
}

void create_kidv_image(const HKdf_t* kdf, const key_idv_t* kidv,
                       secp256k1_gej* out_commitment, uint8_t create_coin_key) {
    if (create_coin_key) {
        secp256k1_scalar  sk;
        // As we would have no asset id, we should have infinitiy (or NULL) h_gen
        switch_commitment_create(&sk, out_commitment, kdf, kidv, 1, NULL);
    } else {
        create_common_kidv_image(kdf, kidv, out_commitment);
    }
}

void switch_commitment_create(secp256k1_scalar* sk, secp256k1_gej* commitment,
                              const HKdf_t* kdf, const key_idv_t* kidv,
                              uint8_t has_commitment,
                              const secp256k1_gej* h_gen) {
    uint8_t hash_id[DIGEST_LENGTH];
    generate_hash_id(kidv->id.idx, kidv->id.type, kidv->id.sub_idx, hash_id);

    derive_key(kdf->generator_secret, DIGEST_LENGTH, hash_id, DIGEST_LENGTH,
               &kdf->cofactor, sk);

    // Multiply key by generator G
    generator_mul_scalar(commitment, get_context()->generator.G_pts, sk);
    tag_add_value(h_gen, kidv->value, commitment);

    // Multiply key by generator J
    secp256k1_gej key_j_mul_result;
    generator_mul_scalar(&key_j_mul_result, get_context()->generator.J_pts, sk);

    secp256k1_scalar sk1;
    switch_commitment_get_sk1(commitment, &key_j_mul_result, &sk1);
    secp256k1_scalar_add(sk, sk, &sk1);

    if (has_commitment) {
        secp256k1_gej sk1_g_mul_result;
        generator_mul_scalar(&sk1_g_mul_result, get_context()->generator.G_pts,
                             &sk1);
        secp256k1_gej_add_var(commitment, commitment, &sk1_g_mul_result, NULL);
    }
}


// AmountBig::Type is 128 bits = 16 bytes
int kernel_traverse(const tx_kernel_t* kernel, const tx_kernel_t* parent_kernel,
                    const uint8_t* hash_lock_preimage, uint8_t* hash_value,
                    uint64_t* fee, secp256k1_gej* excess) {
    if (parent_kernel) {
        // Nested kernel restrictions
        if ((kernel->kernel.min_height > parent_kernel->kernel.min_height) ||
            (kernel->kernel.max_height < parent_kernel->kernel.max_height)) {
            // Parent Height range must be contained in ours
            return 0;
        }
    }

    beam_sha256_ctx hp;
    beam_hash_sha256_init(&hp);
    beam_hash_sha256_write_64(&hp, kernel->kernel.fee);
    beam_hash_sha256_write_64(&hp, kernel->kernel.min_height);
    beam_hash_sha256_write_64(&hp, kernel->kernel.max_height);
    beam_hash_sha256_update(&hp, kernel->kernel.tx_element.commitment.x, DIGEST_LENGTH);
    beam_hash_sha256_write_8(&hp, kernel->kernel.tx_element.commitment.y);
    beam_hash_sha256_write_64(&hp, kernel->kernel.asset_emission);
    const uint8_t is_empty_kernel_hash_lock_preimage =
        memis0(kernel->kernel.hash_lock_preimage, DIGEST_LENGTH);
    const uint8_t is_non_empty_kernel_hash_lock_preimage =
        !is_empty_kernel_hash_lock_preimage;
    beam_hash_sha256_write_8(&hp, is_non_empty_kernel_hash_lock_preimage);

    if (is_non_empty_kernel_hash_lock_preimage) {
        if (!hash_lock_preimage) {
            beam_sha256_ctx hash_lock_ctx;
            beam_hash_sha256_update(&hash_lock_ctx, kernel->kernel.hash_lock_preimage, DIGEST_LENGTH);
            beam_hash_sha256_final(&hash_lock_ctx, hash_value);

            // TODO: if this correct?
            // pLockImage = &hv;
            hash_lock_preimage = hash_value;
        }

        beam_hash_sha256_update(&hp, hash_lock_preimage, DIGEST_LENGTH);
    }

    secp256k1_gej point_excess_nested;
    if (excess) secp256k1_gej_set_infinity(&point_excess_nested);

    const tx_kernel_t* zero_kernel = NULL;
    UNUSED(zero_kernel);
    for (size_t i = 0; i < (size_t)kernel->nested_kernels.length; ++i) {
        const uint8_t should_break = 0;
        beam_hash_sha256_write_8(&hp, should_break);

        // TODO: to implement. Do we really need this on Trezor?
        // const TxKernel& v = *(*it);
        // if (p0Krn && (*p0Krn > v))
        //    return false;
        // p0Krn = &v;

        // if (!v.Traverse(hv, pFee, pExcess ? &ptExcNested : NULL, this, NULL))
        //    return false;

        // hp << hv;
    }
    const uint8_t should_break = 1;
    beam_hash_sha256_write_8(&hp, should_break);
    beam_hash_sha256_final(&hp, hash_value);

    if (excess) {
        secp256k1_gej pt;
        if (!point_import_nnz(&pt, &kernel->kernel.tx_element.commitment)) return 0;

        secp256k1_gej_neg(&point_excess_nested, &point_excess_nested);
        secp256k1_gej_add_var(&point_excess_nested, &point_excess_nested, &pt,
                              NULL);

        if (!signature_is_valid(hash_value, &kernel->kernel.signature,
                                &point_excess_nested,
                                get_context()->generator.G_pts))
            return 0;

        secp256k1_gej_add_var(excess, excess, &pt, NULL);

        // TODO: do we need support for the asset emission? Seems no
        // if (kernel_emission->kernel.asset_emission)
        //{
        // TODO: do we need this on the device?
        // if (!Rules::get().CA.Enabled)
        //    return false;
        //
        // Ban complex cases. Emission kernels must be simple
        // if (parent_kernel || kernel->nested_kernels.length != 0)
        //    return false;
        //}
    }
    if (fee) {
        *fee += kernel->kernel.fee;
    }

    return 1;
}

void kernel_get_hash(const tx_kernel_t* kernel,
                     const uint8_t* hash_lock_preimage, uint8_t* out) {
    kernel_traverse(kernel, NULL, hash_lock_preimage, out, NULL, NULL);
}

// Add the blinding factor and value of a specific TXO
void summarize_once(secp256k1_scalar* res, int64_t* d_val_out, const key_idv_t* kidv,
                    const HKdf_t* kdf) {
    int64_t d_val = *d_val_out;

    secp256k1_scalar sk;
    secp256k1_gej commitment_native;
    printf("Summarize once: about to switch_commitment_create\n");
    switch_commitment_create(&sk, &commitment_native, kdf, kidv, 1, NULL);
    printf("Summarize once: done switch_commitment_create\n");
    // Write results - commitment_native - to TxOutput
    // export_gej_to_point(&commitment_native, &output->tx_element.commitment);

    secp256k1_scalar_add(res, res, &sk);
    d_val += kidv->value;

    *d_val_out = d_val;
}

// Summarize. Summarizes blinding factors and values of several in/out TXOs
void summarize_bf_and_values(secp256k1_scalar* res, int64_t* d_val_out,
                             const key_idv_t* inputs, const size_t num_inputs,
                             const key_idv_t* outputs, const size_t num_outputs,
                             const HKdf_t* kdf) {
    printf("Summarize bf and values: start\n");
    int64_t d_val = *d_val_out;

    printf("Summarize bf and values: sk negate\n");
    secp256k1_scalar_negate(res, res);
    printf("Summarize bf and values: sk negate - done\n");
    d_val = -d_val;

    printf("Summarize bf and values: summarize outputs\n");
    for (uint32_t i = 0; i < num_outputs; ++i)
        summarize_once(res, &d_val, &outputs[i], kdf);
    printf("Summarize bf and values: summarize outputs - done\n");

    printf("Summarize bf and values: sk negate\n");
    secp256k1_scalar_negate(res, res);
    d_val = -d_val;
    printf("Summarize bf and values: sk negate - done\n");

    printf("Summarize bf and values: summarize inputs\n");
    for (uint32_t i = 0; i < num_inputs; ++i)
        summarize_once(res, &d_val, &inputs[i], kdf);
    printf("Summarize bf and values: summarize inputs - done\n");

    *d_val_out = d_val;
}

void summarize_commitment(secp256k1_gej* res,
                          const key_idv_t* inputs, const size_t num_inputs,
                          const key_idv_t* outputs, const size_t num_outputs,
                          const HKdf_t* kdf) {
    secp256k1_scalar sk;
    secp256k1_scalar_clear(&sk);
    int64_t d_val = 0;
    summarize_bf_and_values(&sk, &d_val, inputs, num_inputs, outputs, num_outputs, kdf);

    generator_mul_scalar(res, get_context()->generator.G_pts, &sk);

    if (d_val < 0) {
        secp256k1_gej_neg(res, res);

        // res += Context::get().H * Amount(-dVal);
        secp256k1_scalar sk1;
        secp256k1_scalar_set_u64(&sk1, (uint64_t)d_val * -1);
        secp256k1_scalar_negate(&sk1, &sk1);
        secp256k1_gej sk1_h_mul_result;
        generator_mul_scalar(&sk1_h_mul_result, get_context()->generator.H_pts,
                             &sk1);
        secp256k1_gej_add_var(res, res, &sk1_h_mul_result, NULL);

        secp256k1_gej_neg(res, res);
    } else {
        // res += Context::get().H * Amount(dVal);
        secp256k1_scalar sk1;
        secp256k1_scalar_set_u64(&sk1, (uint64_t)d_val);
        secp256k1_gej sk1_h_mul_result;
        generator_mul_scalar(&sk1_h_mul_result, get_context()->generator.H_pts,
                             &sk1);
        secp256k1_gej_add_var(res, res, &sk1_h_mul_result, NULL);
    }
}

uint8_t is_valid_nonce_slot(uint32_t nonce_slot) {
    if (nonce_slot == MASTER_NONCE_SLOT || nonce_slot > MAX_NONCE_SLOT) {
        return 0;
    }

    return 1;
}

uint8_t sign_transaction_part_1(int64_t* value_transferred, secp256k1_scalar* sk_total,
                                const key_idv_t* inputs, const size_t num_inputs,
                                const key_idv_t* outputs, const size_t num_outputs,
                                const transaction_data_t* tx_data,
                                const HKdf_t* kdf) {
    if (!is_valid_nonce_slot(tx_data->nonce_slot)) return 0;

    secp256k1_scalar offset;
    secp256k1_scalar_negate(&offset, &tx_data->offset);
    memcpy(sk_total, &offset, sizeof(secp256k1_scalar));
    int64_t d_val = 0;

    // calculate the overall blinding factor, and the sum being sent/transferred
    summarize_bf_and_values(sk_total, &d_val, inputs, num_inputs, outputs, num_outputs, kdf);

    *value_transferred = d_val;

    return 1;
}

uint8_t sign_transaction_part_2(secp256k1_scalar* res,
                                const transaction_data_t* tx_data,
                                const secp256k1_scalar* nonce,
                                const secp256k1_scalar* sk_total,
                                const secp256k1_gej* kernel_nonce) {
    if (!is_valid_nonce_slot(tx_data->nonce_slot)) return 0;

    // Calculate the Kernel ID
    tx_kernel_t krn;
    printf("Kernel init!\n");
    kernel_init(&krn);
    printf("Kernel inited!\n");
    krn.kernel.min_height = tx_data->min_height;
    krn.kernel.max_height = tx_data->max_height;
    krn.kernel.fee = tx_data->fee;
    //DEBUG_PRINT("Fee: \n", &tx_data->fee, sizeof(uint64_t));
    memcpy(&krn.kernel.tx_element.commitment, &tx_data->kernel_commitment,
           sizeof(point_t));
    printf("Kernel commitment filled!\n");
    memcpy(&krn.kernel.signature.nonce_pub, kernel_nonce, sizeof(secp256k1_gej));
    printf("Kernel nonce_pub filled!\n");

    // TODO: get exact size of the hash
    uint8_t kernel_hash_value[DIGEST_LENGTH];
    printf("Kernel get hash!\n");
    kernel_get_hash(&krn, NULL, kernel_hash_value);
    printf("Kernel got hash!\n");

    uint8_t sk_data[DIGEST_LENGTH];
    printf("Get sk_data!\n");
    secp256k1_scalar_get_b32(sk_data, sk_total);
    printf("Got sk_data!\n");

    DEBUG_PRINT("Sk total: ", sk_data, DIGEST_LENGTH);
    printf("Fee: %u\nMin height: %u\nMax height: %u\n", (uint32_t)tx_data->fee, (uint32_t)tx_data->min_height, (uint32_t)tx_data->max_height);
    DEBUG_PRINT("Kernel nonce_pub.x: ", tx_data->kernel_nonce.x, DIGEST_LENGTH);
    printf("\tKernel nonce_pub.y: %d\n", tx_data->kernel_nonce.y);
    DEBUG_PRINT("Kernel commitment.x: ", krn.kernel.tx_element.commitment.x,
                DIGEST_LENGTH);
    printf("\tKernel commitment.y: %d\n", krn.kernel.tx_element.commitment.y);
    DEBUG_PRINT("Kernel hash: ", kernel_hash_value, DIGEST_LENGTH);

    // Create partial signature

    printf("Sign partial\n");
    signature_sign_partial(nonce, &krn.kernel.signature.nonce_pub, kernel_hash_value, sk_total, res);
    printf("Signed partial\n");

    return 1;
}
