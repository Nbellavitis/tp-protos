//
// Created by lulos on 6/27/2025.
//

#ifndef TP_PROTOS_MANAGEMENT_H
#define TP_PROTOS_MANAGEMENT_H

#endif //TP_PROTOS_MANAGEMENT_H


/*
CLIENTE → SERVIDOR                                             SERVIDOR → CLIENTE
+-----+-----+------+------+-------------------+      +-----+-------+ ---------------------------------+
| VER | CMD | payload len | Payload (opcional)|      |VER | STATUS | Payload len |Payload (opcional)  |
+-----+-----+------+------+-------------------+      +-----+-------+----------------------------------+
[1]     [1]       [1]        [0..255]                  [1]     [1]             [1]        [0..255]
 */

/*
 *    VER --> solo es valido 0x01
 *    CMD --> Valido de 0x01 hasta .... todo definir
 *    PAYLOAD LEN: Valido de 0x00 hasta 0xFF
 *    Payload: Son como mucho 255 caracteres. Depende del CMD.
 *
 *
 *    Va a por TCP y puede elegir entre usar o no usar Auth. (Negociacion)
 *
 */