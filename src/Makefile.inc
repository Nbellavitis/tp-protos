# ---------- optimisation (default) ----------
CFLAGS_OPT  = -O3 -std=c11 -D_POSIX_C_SOURCE=200112L -D__BSD_VISIBLE=1
LDFLAGS_OPT = -pthread

# ---------- debug / sanitizers --------------
CFLAGS_DEBUG = -g -O0 -std=c11 -D_POSIX_C_SOURCE=200112L -D__BSD_VISIBLE=1 \
               -Wall -Wextra -pedantic -pedantic-errors \
               -Wno-unused-parameter -Wno-implicit-fallthrough \
               -fsanitize=address -DDEBUG
LDFLAGS_DEBUG = -pthread -fsanitize=address -g

# ---------- common libraries ----------------
LDLIBS = -lanl
