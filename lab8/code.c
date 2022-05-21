#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    const char *pam_strerror( pamh, errnum);	 
    pam_handle_t *pamh;
    int errnum;
    int retval;
    const char *user="nobody";

    if(argc == 2) {
	    user = argv[1];
    }

    if(argc > 2) {
      fprintf(stderr, "Usage: check_user [username]\n");
      exit(1);
    }

    retval = pam_start("check", user, &conv, &pamh);

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user == user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* access? */

    /* Authorization */

    if (retval == PAM_SUCCESS) {
	    fprintf(stdout, "Authention is successful\n");
    } 
    else {
	    fprintf(stdout, "Authenticated failed\n");
    }

    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
	pamh = NULL;
	fprintf(stderr, "check_user: failed to release authenticator\n");
	exit(1);
    }
    printf("error code: %s\n", pam_strerror(pamh, retval));

    return ( retval == PAM_SUCCESS ? 0:1 );       /* success? */
}
