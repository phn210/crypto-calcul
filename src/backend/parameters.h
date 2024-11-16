#ifdef PARAM_L0
#define PARAM_SECURITY 112
#endif
#ifdef PARAM_L1
#define PARAM_SECURITY 128
#endif
#ifdef PARAM_L3
#define PARAM_SECURITY 192
#endif
#ifdef PARAM_L5
#define PARAM_SECURITY 256
#error "Security level not identified"
#endif