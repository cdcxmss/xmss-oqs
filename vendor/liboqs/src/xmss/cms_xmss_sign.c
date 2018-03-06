/* Simple XMSS S/MIME signing example */
#include "xmss.c" // order of #includes matters!
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(void)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;

    load_xmss_all();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
     tbio = BIO_new_file("cert_xmss.pem", "r");
    fprintf(stderr, "[cms_xmss_sign] Read signer certificate and private key in cert_xmss.pem\n");

    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    tbio = BIO_new_file("sk_xmss.pem", "r");
    fprintf(stderr, "[cms_xmss_sign] Read sk_xmss.pem\n");

    if (!tbio)
        goto err;
    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */

    in = BIO_new_file("sign_xmss.txt", "r");
    fprintf(stderr, "[cms_xmss_sign] Open content being signed: sign_xmss.txt\n");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);
    fprintf(stderr, "[cms_xmss_sign] Performed CMS_sign\n");

    if (!cms)
        goto err;

    out = BIO_new_file("smout_xmss.txt", "w");

    if (!out)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;
    fprintf(stderr, "[cms_xmss_sign] Wrote out S/MIME message to smout_xmss.txt\n");
    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "[cms_sign_xmss] Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);
    if (scert)
        X509_free(scert);
    if (skey)
        EVP_PKEY_free(skey);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);
    if (tbio)
        BIO_free(tbio);

    return ret;

}
