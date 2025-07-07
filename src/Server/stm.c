/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdlib.h>
#include "stm.h"
#include <stdio.h>
#include "../logger.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

void
stm_init(struct state_machine *stm) {
    // verificamos que los estados son correlativos, y que están bien asignados.
    for(unsigned i = 0 ; i <= stm->max_state; i++) {
        if(i != stm->states[i].state) {
            abort();
        }
    }

    if(stm->initial < stm->max_state) {
        stm->current = NULL;
    } else {
        abort();
    }
}

inline static void
handle_first(struct state_machine *stm, struct selector_key *key) {
    if(stm->current == NULL) {
        stm->current = stm->states + stm->initial;
        if(NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

inline static
void jump(struct state_machine *stm, unsigned next, struct selector_key *key) {
    if(next > stm->max_state) {
        abort();
    }
    if(stm->current != stm->states + next) {
        if(stm->current != NULL && stm->current->on_departure != NULL) {
            stm->current->on_departure(stm->current->state, key);
        }
        stm->current = stm->states + next;

        if(NULL != stm->current->on_arrival) {
            stm->current->on_arrival(stm->current->state, key);
        }
    }
}

unsigned
stm_handler_read(struct state_machine *stm, struct selector_key *key) {
    handle_first(stm, key);
    if(stm->current->on_read_ready == 0) {
       LOG_DEBUG("Estado %d sin on_read_ready", stm->current->state);
        abort();
    }
    const unsigned int ret = stm->current->on_read_ready(key);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_write(struct state_machine *stm, struct selector_key *key) {
    LOG_DEBUG("stm_handler_write: Entrando");
    handle_first(stm, key);
    LOG_DEBUG("stm_handler_write: Estado actual: %d", stm->current->state);
    LOG_DEBUG("stm_handler_write: on_write_ready: %p", (void*)stm->current->on_write_ready);
    if(stm->current->on_write_ready == 0) {
        LOG_DEBUG("stm_handler_write: on_write_ready es NULL");
        abort();
    }
    LOG_DEBUG("stm_handler_write: Llamando a on_write_ready");
    const unsigned int ret = stm->current->on_write_ready(key);
    LOG_DEBUG("stm_handler_write: on_write_ready retornó: %d", ret);
    jump(stm, ret, key);

    return ret;
}

unsigned
stm_handler_block(struct state_machine *stm, struct selector_key *key) {
    LOG_DEBUG("stm_handler_block: Entrando");
    handle_first(stm, key);
    LOG_DEBUG("stm_handler_block: Estado actual: %d", stm->current->state);
    LOG_DEBUG("stm_handler_block: on_block_ready: %p", (void*)stm->current->on_block_ready);
    if(stm->current->on_block_ready == 0) {
        LOG_DEBUG("stm_handler_block: on_block_ready es NULL");
        abort();
    }
    LOG_DEBUG("stm_handler_block: Llamando a on_block_ready");
    const unsigned int ret = stm->current->on_block_ready(key);
    LOG_DEBUG("stm_handler_block: on_block_ready retornó: %d", ret);
    jump(stm, ret, key);

    return ret;
}

void
stm_handler_close(struct state_machine *stm, struct selector_key *key) {
    if(stm->current != NULL && stm->current->on_departure != NULL) {
        stm->current->on_departure(stm->current->state, key);
    }
}

unsigned
stm_state(struct state_machine *stm) {
    unsigned ret = stm->initial;
    if(stm->current != NULL) {
        ret= stm->current->state;
    }
    return ret;
}
