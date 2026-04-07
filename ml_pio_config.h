/**
 * PlatformIO build overrides for MicroLink v2 Kconfig values.
 * Included via -include flag in library.json.
 */
#ifndef ML_PIO_CONFIG_H
#define ML_PIO_CONFIG_H

/* String configs that Kconfig normally provides */
#ifndef CONFIG_ML_PRIORITY_PEER_IP
#define CONFIG_ML_PRIORITY_PEER_IP ""
#endif

#ifndef CONFIG_ML_DEVICE_NAME
#define CONFIG_ML_DEVICE_NAME ""
#endif

#endif /* ML_PIO_CONFIG_H */
