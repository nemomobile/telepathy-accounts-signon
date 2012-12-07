#include "config.h"

#include <gio/gio.h>

#include <telepathy-glib/telepathy-glib.h>

#include <libaccounts-glib/ag-account.h>

#include "empathy-webcredentials-monitor.h"

G_DEFINE_TYPE (EmpathyWebcredentialsMonitor, empathy_webcredentials_monitor, G_TYPE_OBJECT)

#define WEBCRED_BUS_NAME "com.canonical.indicators.webcredentials"
#define WEBCRED_PATH "/com/canonical/indicators/webcredentials"
#define WEBCRED_IFACE "com.canonical.indicators.webcredentials"

#define FAILURES_PROP "Failures"

enum
{
  PROP_MANAGER = 1,
  N_PROPS
};

enum
{
  SIG_FAILURE_ADDED,
  SIG_FAILURE_REMOVED,
  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

struct _EmpathyWebcredentialsMonitorPriv
{
  AgManager *manager;
  GDBusProxy *proxy;

  /* array of owned AgAccount */
  GPtrArray *failures;
};

static void
empathy_webcredentials_monitor_get_property (GObject *object,
    guint property_id,
    GValue *value,
    GParamSpec *pspec)
{
  EmpathyWebcredentialsMonitor *self = EMPATHY_WEBCREDENTIALS_MONITOR (object);

  switch (property_id)
    {
      case PROP_MANAGER:
        g_value_set_object (value, self->priv->manager);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
empathy_webcredentials_monitor_set_property (GObject *object,
    guint property_id,
    const GValue *value,
    GParamSpec *pspec)
{
  EmpathyWebcredentialsMonitor *self = EMPATHY_WEBCREDENTIALS_MONITOR (object);

  switch (property_id)
    {
      case PROP_MANAGER:
        g_assert (self->priv->manager == NULL); /* construct only */
        self->priv->manager = g_value_dup_object (value);
        break;
      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
empathy_webcredentials_monitor_constructed (GObject *object)
{
  EmpathyWebcredentialsMonitor *self = EMPATHY_WEBCREDENTIALS_MONITOR (object);
  void (*chain_up) (GObject *) =
      ((GObjectClass *) empathy_webcredentials_monitor_parent_class)->constructed;

  chain_up (object);

  g_assert (AG_IS_MANAGER (self->priv->manager));
}

static void
empathy_webcredentials_monitor_dispose (GObject *object)
{
  EmpathyWebcredentialsMonitor *self = EMPATHY_WEBCREDENTIALS_MONITOR (object);
  void (*chain_up) (GObject *) =
      ((GObjectClass *) empathy_webcredentials_monitor_parent_class)->dispose;

  g_clear_object (&self->priv->manager);
  g_clear_object (&self->priv->proxy);

  chain_up (object);
}

static void
empathy_webcredentials_monitor_finalize (GObject *object)
{
  EmpathyWebcredentialsMonitor *self = EMPATHY_WEBCREDENTIALS_MONITOR (object);
  void (*chain_up) (GObject *) =
      ((GObjectClass *) empathy_webcredentials_monitor_parent_class)->finalize;

  g_ptr_array_unref (self->priv->failures);

  chain_up (object);
}

static void
empathy_webcredentials_monitor_class_init (
    EmpathyWebcredentialsMonitorClass *klass)
{
  GObjectClass *oclass = G_OBJECT_CLASS (klass);
  GParamSpec *spec;

  oclass->get_property = empathy_webcredentials_monitor_get_property;
  oclass->set_property = empathy_webcredentials_monitor_set_property;
  oclass->constructed = empathy_webcredentials_monitor_constructed;
  oclass->dispose = empathy_webcredentials_monitor_dispose;
  oclass->finalize = empathy_webcredentials_monitor_finalize;

  spec = g_param_spec_object ("manager", "Manager",
      "AgManager",
      AG_TYPE_MANAGER,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
  g_object_class_install_property (oclass, PROP_MANAGER, spec);

  signals[SIG_FAILURE_ADDED] = g_signal_new ("failure-added",
      G_OBJECT_CLASS_TYPE (klass),
      G_SIGNAL_RUN_LAST,
      0, NULL, NULL, NULL,
      G_TYPE_NONE,
      1, AG_TYPE_ACCOUNT);

  signals[SIG_FAILURE_REMOVED] = g_signal_new ("failure-removed",
      G_OBJECT_CLASS_TYPE (klass),
      G_SIGNAL_RUN_LAST,
      0, NULL, NULL, NULL,
      G_TYPE_NONE,
      1, AG_TYPE_ACCOUNT);

  g_type_class_add_private (klass, sizeof (EmpathyWebcredentialsMonitorPriv));
}

static void
update_failures (EmpathyWebcredentialsMonitor *self)
{
  GVariant *failures, *f;
  GVariantIter iter;
  GList *new_list = NULL;
  guint i;

  failures = g_dbus_proxy_get_cached_property (self->priv->proxy,
      FAILURES_PROP);
  if (failures == NULL)
    {
      g_debug ("Does not implement Failures property");
      return;
    }

  g_variant_iter_init (&iter, failures);
  while ((f = g_variant_iter_next_value (&iter)) != NULL)
    {
      guint32 id;
      AgAccount *account;

      id = g_variant_get_uint32 (f);

      account = ag_manager_get_account (self->priv->manager, id);
      if (account == NULL)
        continue;

      /* Pass ownership of 'account' to the list */
      new_list = g_list_append (new_list, account);

      if (!tp_g_ptr_array_contains (self->priv->failures, account))
        {
          g_ptr_array_add (self->priv->failures, g_object_ref (account));

          g_signal_emit (self, signals[SIG_FAILURE_ADDED], 0, account);
        }

      g_variant_unref (f);
    }

  g_variant_unref (failures);

  for (i = 0; i < self->priv->failures->len; i++)
    {
      AgAccount *account = g_ptr_array_index (self->priv->failures, i);

      if (g_list_find (new_list, account) == NULL)
        {
          g_object_ref (account);
          g_ptr_array_remove (self->priv->failures, account);

          g_signal_emit (self, signals[SIG_FAILURE_REMOVED], 0, account);
          g_object_unref (account);
        }
    }

  g_list_free_full (new_list, g_object_unref);
}

static void
properties_changed_cb (GDBusProxy *proxy,
    GVariant *changed_properties,
    GStrv invalidated_properties,
    EmpathyWebcredentialsMonitor *self)
{
  if (g_variant_lookup_value (changed_properties, FAILURES_PROP, NULL) == NULL)
    return;

  update_failures (self);
}

static void
proxy_new_cb (GObject *source,
    GAsyncResult *result,
    gpointer user_data)
{
  EmpathyWebcredentialsMonitor *self;
  TpWeakRef *wr = user_data;
  GError *error = NULL;

  self = tp_weak_ref_dup_object (wr);
  if (self == NULL)
    goto out;

  self->priv->proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
  if (self->priv->proxy == NULL)
    {
      g_debug ("Failed to create webcredentials proxy: %s", error->message);
      g_error_free (error);
      goto out;
    }

  update_failures (self);

  g_signal_connect (self->priv->proxy, "g-properties-changed",
      G_CALLBACK (properties_changed_cb), self);

out:
  tp_weak_ref_destroy (wr);
  g_clear_object (&self);
}

static void
empathy_webcredentials_monitor_init (EmpathyWebcredentialsMonitor *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      EMPATHY_TYPE_WEBCREDENTIALS_MONITOR, EmpathyWebcredentialsMonitorPriv);

  self->priv->failures = g_ptr_array_new_with_free_func (g_object_unref);

  g_dbus_proxy_new_for_bus (G_BUS_TYPE_SESSION, G_DBUS_PROXY_FLAGS_NONE, NULL,
      WEBCRED_BUS_NAME, WEBCRED_PATH, WEBCRED_IFACE,
      NULL, proxy_new_cb, tp_weak_ref_new (self, NULL, NULL));
}

EmpathyWebcredentialsMonitor *
empathy_webcredentials_monitor_new (AgManager *manager)
{
  return g_object_new (EMPATHY_TYPE_WEBCREDENTIALS_MONITOR,
      "manager", manager,
      NULL);
}

GPtrArray *
empathy_webcredentials_get_failures (EmpathyWebcredentialsMonitor *self)
{
  return self->priv->failures;
}
