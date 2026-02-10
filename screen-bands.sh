#!/bin/bash
# screen-bands.sh - Bandas negras usando NVIDIA ViewPortOut
# Uso:
#   ./screen-bands.sh on <ancho> <alto>    - Activa bandas negras
#   ./screen-bands.sh off                   - Restaura pantalla completa
#
# Ejemplos:
#   ./screen-bands.sh on 1920 1080          - Bandas laterales + abajo
#   ./screen-bands.sh on 1600 1320          - Bandas laterales + abajo
#   ./screen-bands.sh off                   - Volver a 2560x1440

set -euo pipefail

NATIVE_W=2560
NATIVE_H=1440
DISPLAY_DPY="DPY-4"

case "${1:-help}" in
    on)
        if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
            echo "Uso: $0 on <ancho> <alto>"
            echo "  Resolución nativa: ${NATIVE_W}x${NATIVE_H}"
            echo "  Ejemplo: $0 on 1600 1320"
            exit 1
        fi

        TARGET_W="$2"
        TARGET_H="$3"

        if [ "$TARGET_W" -gt "$NATIVE_W" ] || [ "$TARGET_H" -gt "$NATIVE_H" ]; then
            echo "Error: La resolución objetivo debe ser menor o igual que ${NATIVE_W}x${NATIVE_H}"
            exit 1
        fi

        # Centrado horizontal, pegado arriba (banda abajo)
        POS_X=$(( (NATIVE_W - TARGET_W) / 2 ))
        POS_Y=0

        echo "Nativa:      ${NATIVE_W}x${NATIVE_H}"
        echo "Objetivo:    ${TARGET_W}x${TARGET_H}"
        echo "Banda izq:   ${POS_X}px"
        echo "Banda der:   ${POS_X}px"
        echo "Banda abajo: $((NATIVE_H - TARGET_H))px"
        echo ""

        METAMODE="${DISPLAY_DPY}: nvidia-auto-select @${TARGET_W}x${TARGET_H} +0+0 {ViewPortIn=${TARGET_W}x${TARGET_H}, ViewPortOut=${TARGET_W}x${TARGET_H}+${POS_X}+${POS_Y}}"

        echo "Aplicando: $METAMODE"
        nvidia-settings --assign CurrentMetaMode="$METAMODE"

        echo ""
        echo "Bandas activadas. Usa '$0 off' para restaurar."
        ;;

    off)
        echo "Restaurando ${NATIVE_W}x${NATIVE_H}..."

        METAMODE="${DISPLAY_DPY}: nvidia-auto-select @${NATIVE_W}x${NATIVE_H} +0+0 {ViewPortIn=${NATIVE_W}x${NATIVE_H}, ViewPortOut=${NATIVE_W}x${NATIVE_H}+0+0}"

        nvidia-settings --assign CurrentMetaMode="$METAMODE"
        echo "Restaurado."
        ;;

    *)
        echo "Uso:"
        echo "  $0 on <ancho> <alto>   - Activar bandas negras"
        echo "  $0 off                  - Restaurar pantalla completa"
        echo ""
        echo "Ejemplos:"
        echo "  $0 on 1920 1080         - Simular 1080p con bandas"
        echo "  $0 on 1600 1320         - Área reducida con bandas"
        echo "  $0 off                  - Volver a 2560x1440"
        ;;
esac
