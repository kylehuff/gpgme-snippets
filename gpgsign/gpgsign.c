/*
    To compile this snippet, simply execute `gcc gpgsign.c -lgpgme -o gpgsign`
    in the same directory as this file.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <locale.h>

#include <gpgme.h>

#define fail_if_err(err)                                    \
    do {                                                    \
        if (err) {                                          \
            fprintf (stderr, "%s:%d: %s: %s\n",             \
                __FILE__, __LINE__, gpgme_strsource (err),  \
                gpgme_strerror (err));                      \
            exit (1);                                       \
        }                                                   \
    }                                                       \
    while (0)

void gpgSign(const char *keyID, const char *textToSign) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out, result;
    gpgme_verify_result_t verify_result;
    gpgme_signature_t sig;
    int tnsigs, nsigs;
    int BUF_SIZE = 512;
    char buf[BUF_SIZE + 1];
    int ret;
    /* Set the GPGME signature mode
        GPGME_SIG_MODE_NORMAL : Signature with data
        GPGME_SIG_MODE_CLEAR  : Clear signed text
        GPGME_SIG_MODE_DETACH : Detached signature */
    gpgme_sig_mode_t sigMode = GPGME_SIG_MODE_CLEAR;

    /* Begin setup of GPGME */
    gpgme_check_version (NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
    /* End setup of GPGME */

    err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);
    fail_if_err (err);
    
    // Create the GPGME Context
    err = gpgme_new (&ctx);
    // Error handling
    fail_if_err (err);

    // Set the context to textmode
    gpgme_set_textmode (ctx, 1);
    // Enable ASCII armor on the context
    gpgme_set_armor (ctx, 1);

    unsigned int textLength = strlen (textToSign);

    // Create a data object that contains the text to sign
    err = gpgme_data_new_from_mem (&in, textToSign, textLength, 0);
    // Error handling
    fail_if_err (err);

    // Create a data object pointing to the out buffer
    err = gpgme_data_new (&out);
    // Error handling
    fail_if_err (err);

    // Create a data object pointing to the result buffer
    err = gpgme_data_new (&result);
    // Error handling
    fail_if_err (err);

    // Sign the contents of "in" using the defined mode and place it into "out"
    err = gpgme_op_sign (ctx, in, out, sigMode);
    // Error handling
    fail_if_err (err);

    // Rewind the "out" data object
    ret = gpgme_data_seek (out, 0, SEEK_SET);
    // Error handling
    if (ret)
        fail_if_err (gpgme_err_code_from_errno (errno));

    // Read the contents of "out" and place it into buf
    while ((ret = gpgme_data_read (out, buf, BUF_SIZE)) > 0) {
        // Write the contents of "buf" to the console
        fwrite (buf, ret, 1, stdout);
    }

    fwrite ("\n", 1, 1, stdout);

    // Error handling
    if (ret < 0)
        fail_if_err (gpgme_err_code_from_errno (errno));

    // Rewind the "out" data object
    ret = gpgme_data_seek (out, 0, SEEK_SET);

    // Perform a decrypt/verify action
    err = gpgme_op_decrypt_verify (ctx, out, result);

    // Retrieve the verification result
    verify_result = gpgme_op_verify_result (ctx);

    // Error handling
    if (err != GPG_ERR_NO_ERROR && !verify_result)
        fail_if_err (err);

    // Check if the verify_result object has signatures
    if (verify_result && verify_result->signatures) {
        // Iterate through the signatures in the verify_result object
        for (nsigs=0, sig=verify_result->signatures; sig; sig = sig->next, nsigs++) {
            fprintf(stdout, "Signature made with Key: %s\n", sig->fpr);
            fprintf(stdout, "Created: %lu; Expires %lu\n", sig->timestamp, sig->exp_timestamp);
            char *validity = sig->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                    sig->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                    sig->validity == GPGME_VALIDITY_NEVER? "never":
                    sig->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                    sig->validity == GPGME_VALIDITY_FULL? "full":
                    sig->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
            char *sig_status = gpg_err_code (sig->status) == GPG_ERR_NO_ERROR? "GOOD":
                    gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE? "BAD_SIG":
                    gpg_err_code (sig->status) == GPG_ERR_NO_PUBKEY? "NO_PUBKEY":
                    gpg_err_code (sig->status) == GPG_ERR_NO_DATA? "NO_SIGNATURE":
                    gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED? "GOOD_EXPSIG":
                    gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED? "GOOD_EXPKEY": "INVALID";
            fprintf(stdout, "Validity: %s; Signature Status: %s", validity, sig_status);
            fwrite("\n", 1, 1, stdout);
            tnsigs++;
        }
    }

    if (err != GPG_ERR_NO_ERROR && tnsigs < 1)
        fail_if_err(err);

    // Release the "in" data object
    gpgme_data_release (in);
    // Release the "out" data object
    gpgme_data_release (out);

    // Release the context
    gpgme_release (ctx);
}

int 
main (int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: gpgsign <key id> <text>\n");
        exit (1);
    }
    printf("Signing \"%s\" with key %s\n", argv[2], argv[1]);
    gpgSign(argv[1], argv[2]);
    return 0;
}
