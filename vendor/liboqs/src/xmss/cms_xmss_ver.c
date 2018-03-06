/* Simple XMSS S/MIME verification example */
#include "xmss.c" // order of includes matters!
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(void)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;

    load_xmss_all();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in CA certificate */
    tbio = BIO_new_file("cert_xmss.pem", "r");
    fprintf(stderr, "[cms_xmss_ver] Read CA certificate in cert_xmss.pem\n");

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open message being verified */

    in = BIO_new_file("smout_xmss.txt", "r");
    fprintf(stderr, "[cms_xmss_ver] Open message being verified: smout_xmss.txt\n");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file("smver_xmss.txt", "w");
    fprintf(stderr, "[cms_xmss_ver] Output verified content to smver_xmss.txt\n");
    if (!out)
        goto err;

    if (!CMS_verify(cms, NULL, st, cont, out, 0)) {
        fprintf(stderr, "[cms_xmss_ver] Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "[cms_xmss_ver] Verification Successful\n");

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "[cms_xmss_ver] Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);

    if (cacert)
        X509_free(cacert);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);
    if (tbio)
        BIO_free(tbio);

    return ret;

}
