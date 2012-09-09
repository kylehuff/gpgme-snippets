#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
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

void gpgSign(const char *fileToBeSigned, const char *outputFileName) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    FILE *outputFile;
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

    if (!err && err == GPG_ERR_NO_ERROR) {
        printf("Success\n");
    } else {
        printf("%i; %i: %s\n", GPG_ERR_NO_ERROR, gpgme_err_code (err), gpgme_strerror (err));
    } 

    // Create the GPGME Context
    err = gpgme_new (&ctx);
    // Error handling
    fail_if_err (err);

    // Set the context to textmode
    gpgme_set_textmode (ctx, 1);
    // Enable ASCII armor on the context
    gpgme_set_armor (ctx, 1);

    // Create a data object pointing to the input file
    err = gpgme_data_new_from_file (&in, fileToBeSigned, 1);
    // Error handling
    fail_if_err (err);

    // Create a data object pointing to the out buffer
    err = gpgme_data_new (&out);
    // Error handling
    fail_if_err (err);

    // Sign the contents of "in" using the defined mode and place it into "out"
    err = gpgme_op_sign (ctx, in, out, sigMode);
    // Error handling
    fail_if_err (err);

    // Open the output file
    outputFile = fopen (outputFileName, "w+");

    // Rewind the "out" data object
    ret = gpgme_data_seek (out, 0, SEEK_SET);
    // Error handling
    if (ret)
        fail_if_err (gpgme_err_code_from_errno (errno));

    // Read the contents of "out" and place it into buf
    while ((ret = gpgme_data_read (out, buf, BUF_SIZE)) > 0) {
        // Write the contents of "buf" to "outputFile"
        fwrite (buf, ret, 1, outputFile);
    }

    // Error handling
    if (ret < 0)
        fail_if_err (gpgme_err_code_from_errno (errno));

    // Close "outputFile"
    fclose(outputFile);
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
        printf("Usage: gpgsign <input file> <output file>\n");
        exit (1);
    }
    printf("Signing %s and placing the result into %s\n", argv[0], argv[1]);
    gpgSign(argv[1], argv[2]);
    return 0;
}
