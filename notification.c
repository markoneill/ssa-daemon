#include <libnotify/notify.h>
#include "notification.h"


int connect_phone_alert() {
	notify_init ("Please connect your phone");
	NotifyNotification * Hello = notify_notification_new ("Please connect your phone", "Please connect your phone to use ClientAuth", "dialog-information");
	notify_notification_show (Hello, NULL);
	g_object_unref(G_OBJECT(Hello));
	notify_uninit();
	return 0;
}

#if _DEBUG
int main(){
	connect_phone_alert();
}
#endif
