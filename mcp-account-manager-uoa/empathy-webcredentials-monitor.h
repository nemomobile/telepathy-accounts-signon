#ifndef __EMPATHY_WEBCREDENTIALS_MONITOR_H__
#define __EMPATHY_WEBCREDENTIALS_MONITOR_H__

#include <glib-object.h>

#include <libaccounts-glib/ag-manager.h>

G_BEGIN_DECLS

typedef struct _EmpathyWebcredentialsMonitor EmpathyWebcredentialsMonitor;
typedef struct _EmpathyWebcredentialsMonitorClass EmpathyWebcredentialsMonitorClass;
typedef struct _EmpathyWebcredentialsMonitorPriv EmpathyWebcredentialsMonitorPriv;

struct _EmpathyWebcredentialsMonitorClass
{
  /*<private>*/
  GObjectClass parent_class;
};

struct _EmpathyWebcredentialsMonitor
{
  /*<private>*/
  GObject parent;
  EmpathyWebcredentialsMonitorPriv *priv;
};

GType empathy_webcredentials_monitor_get_type (void);

/* TYPE MACROS */
#define EMPATHY_TYPE_WEBCREDENTIALS_MONITOR \
  (empathy_webcredentials_monitor_get_type ())
#define EMPATHY_WEBCREDENTIALS_MONITOR(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), \
    EMPATHY_TYPE_WEBCREDENTIALS_MONITOR, \
    EmpathyWebcredentialsMonitor))
#define EMPATHY_WEBCREDENTIALS_MONITOR_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass), \
    EMPATHY_TYPE_WEBCREDENTIALS_MONITOR, \
    EmpathyWebcredentialsMonitorClass))
#define EMPATHY_IS_WEBCREDENTIALS_MONITOR(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
    EMPATHY_TYPE_WEBCREDENTIALS_MONITOR))
#define EMPATHY_IS_WEBCREDENTIALS_MONITOR_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass), \
    EMPATHY_TYPE_WEBCREDENTIALS_MONITOR))
#define EMPATHY_WEBCREDENTIALS_MONITOR_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), \
    EMPATHY_TYPE_WEBCREDENTIALS_MONITOR, \
    EmpathyWebcredentialsMonitorClass))

EmpathyWebcredentialsMonitor * empathy_webcredentials_monitor_new (
    AgManager *manager);

GPtrArray * empathy_webcredentials_get_failures (
    EmpathyWebcredentialsMonitor *self);

G_END_DECLS

#endif /* #ifndef __EMPATHY_WEBCREDENTIALS_MONITOR_H__*/
