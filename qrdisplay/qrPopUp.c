#include <gtk/gtk.h>
#include "../auth_daemon.h"

#define SCALE 486
int 
main(int   argc,
     char *argv[])
{
  
  int pid;
  GtkWidget *window;
  GtkWidget *layout;
  GtkWidget *text;
  GtkWidget *sourceImage;
  GtkWidget *image;
  GdkPixbuf *pixbuf;
  GError    *error;
  int a = 0;
  char ** av; 

  setgid(100);
  setuid(1000);

  gtk_init (&a, &av);
  
  window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_default_size(GTK_WINDOW (window), SCALE , SCALE);  
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_window_set_title (GTK_WINDOW (window), "See Instructions on Phone");
  
  layout = gtk_layout_new(NULL,NULL);
  gtk_container_add(GTK_CONTAINER (window),layout);
  
  gtk_widget_show  (layout);
  pixbuf = gdk_pixbuf_new_from_file_at_scale(IMG_PATH
		  ,SCALE,SCALE,1,&error);

  image = gtk_image_new_from_pixbuf(pixbuf); 
  gtk_layout_put(GTK_LAYOUT (layout), image, 0, 0);
	  
  gtk_widget_show_all(window);
  gtk_main ();
  return 0;
}

/**
 * How to close a GtkWindow
 * Depends what you want to do:
 * gtk.main_quit() will totally kill the program
 * gtk.window.destroy() will destroy the window but keep the program running
 * gtk.window.hide() will hide the window so it can be opened again
 */
