#ifdef CLIENT_AUTH
#include <errno.h>
#include <libnotify/notify.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "log.h"

#define NOTIFICATION_TITLE	"No authentication device"
#define NOTIFICATION_TEXT_1	"To connect with Securely, open the app and connect to "
#define NOTIFICATION_TEXT_2	"To connect with Securely, open the app and connect to your computer"
#define NOTIFICATION_MAX_LEN	256
#define NOTIFICATION_LEN_1	strlen(NOTIFICATION_TEXT_1)

#define D_BUSS_ADDRESS		"DBUS_SESSION_BUS_ADDRESS"

int dispatch_notification();

int connect_phone_alert() {
	struct passwd *data;
	char buf[50];
	char cmd_buf[256];
	size_t bufsize = 50;
	FILE* cmd_out;
	int pid, err;
	uid_t saved_uid;

	saved_uid = geteuid();

	getlogin_r(buf, bufsize);
	data = getpwnam(buf);

	snprintf(cmd_buf, 256, "pgrep -u %s dbus-daemon", buf);
	cmd_out = popen(cmd_buf, "r"); fgets(buf, 50, cmd_out);
	pclose(cmd_out);

	pid = strtoul(buf, NULL, 10);

	snprintf(cmd_buf, 256,
		"grep -z DBUS_SESSION_BUS_ADDRESS /proc/%d/environ | sed -e s/DBUS_SESSION_BUS_ADDRESS=//", pid);
	cmd_out = popen(cmd_buf, "r");
	fgets(cmd_buf, 256, cmd_out);
	pclose(cmd_out);

	if ((err = setenv(D_BUSS_ADDRESS, cmd_buf, TRUE)) < 0) {
		log_printf(LOG_ERROR, "setenv error %d\n", err);
		return -1;
	}
	if ((err = seteuid(data->pw_uid)) < 0) {
		log_printf(LOG_ERROR, "setuid failed with err %d\n", err);
	}
	dispatch_notification();
	if ((err = seteuid(saved_uid)) < 0) {
		log_printf(LOG_ERROR, "setuid(%d) failed\n", err);
		return -1;
	}
	
	return 0;
}

int dispatch_notification() {
	GError *err;
	char note_text[NOTIFICATION_MAX_LEN];
	NotifyNotification * message;

	strcpy(note_text, NOTIFICATION_TEXT_1);
	if (gethostname(&note_text[NOTIFICATION_LEN_1],
			NOTIFICATION_MAX_LEN - NOTIFICATION_LEN_1) < 0) {
		log_printf(LOG_ERROR, "Failed to get hostname: %s\n", strerror(errno));
		strcpy(note_text, NOTIFICATION_TEXT_2);
	}

	err = NULL;
	notify_init (NOTIFICATION_TITLE);
	message = notify_notification_new (
			NOTIFICATION_TITLE,
			note_text,
			"dialog-information");
	notify_notification_show (message, &err);
	if (err != NULL) {
		log_printf(LOG_ERROR, "%s\n", err->message);
	}
	g_object_unref(G_OBJECT(message));
	notify_uninit();
	return 0;
}

#if _DEBUG
int main(){
	connect_phone_alert();
}
#endif //DEBUG

#endif //CLIENT_AUTH

