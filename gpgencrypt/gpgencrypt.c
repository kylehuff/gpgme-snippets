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

typedef char * string;

void gpgEncrypt(const char *fileToEncrypt, const char *outputFileName,
                char *encryptTo[],
                int encryptToLength) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_encrypt_result_t enc_result;
    FILE *outputFile;
    gpgme_key_t keys[encryptToLength];
    int nrecipients = 0;
    int BUF_SIZE = 512;
    char buf[BUF_SIZE + 1];
    int ret;

    /* Begin setup of GPGME */
    gpgme_check_version (NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
    /* End setup of GPGME */

    // Create the GPGME Context
    err = gpgme_new (&ctx);
    // Error handling
    fail_if_err (err);

    // Set the context to textmode
    gpgme_set_textmode (ctx, 1);
    // Enable ASCII armor on the context
    gpgme_set_armor (ctx, 1);

    // Create a data object pointing to the input file
    err = gpgme_data_new_from_file (&in, fileToEncrypt, 1);
    // Error handling
    fail_if_err (err);

    // Create a data object pointing to the out buffer
    err = gpgme_data_new (&out);
    // Error handling
    fail_if_err (err);

    // Retrieve the keys used to encrypt to
    for (nrecipients=0; nrecipients < encryptToLength; nrecipients++) {
        printf("Retrieving key: %s, %i of %i\n", encryptTo[nrecipients], nrecipients, encryptToLength);
        err = gpgme_get_key (ctx, encryptTo[nrecipients], &keys[nrecipients], 0);
        
        if(err != GPG_ERR_NO_ERROR)
            printf("error");
    }

    // NULL terminate the key array
    keys[nrecipients] = NULL;

    // Encrypt the contents of "in" using the defined mode and place it into "out"
    err = gpgme_op_encrypt (ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    // Error handling
    fail_if_err (err);
    
    // Retrieve the encrypt result from the context
    enc_result = gpgme_op_encrypt_result (ctx);
    
    // Check for invalid recipients
    if (enc_result->invalid_recipients) {
        fail_if_err (err);
    }

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

    // Unreference the key objects
    for (nrecipients=0; nrecipients < sizeof(&keys) / sizeof(int) + 1; nrecipients++) {
        if (keys[nrecipients]) {
            printf ("Releasing key: %s\n", keys[nrecipients]->subkeys->fpr);
            gpgme_key_unref (keys[nrecipients]);
        }
    }
    
    // Release the "in" data object
    gpgme_data_release (in);
    // Release the "out" data object
    gpgme_data_release (out);
    // Release the context
    gpgme_release (ctx);
}

int 
main (int argc, char **argv) {
    if (argc < 4) {
        printf ("Usage: gpgencrypt <input file> <output file> <encrypt to>\n");
        exit (1);
    }
    int pos, n;
    string encryptToList[argc - 4];

    printf ("Encrypting %s and placing the result into %s\n",
                argv[1], argv[2]);

    for (pos=3; pos < argc; pos++) {
        encryptToList[n] = argv[pos];
        n++;
    }
    gpgEncrypt (argv[1], argv[2], encryptToList, argc - 3);
    return 0;
}
